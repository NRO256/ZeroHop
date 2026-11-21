//! テーマ・DPIスケーリング・フォント・ハイコントラスト・アイコン・配置管理。

use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, RECT};
use windows_sys::Win32::Graphics::Dwm::{
    DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute,
};
use windows_sys::Win32::Graphics::Gdi::{
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, CreateFontIndirectW, CreateSolidBrush, DEFAULT_CHARSET,
    DEFAULT_PITCH, DeleteObject, EnumFontFamiliesExW, FW_BOLD, FW_NORMAL, GetDC, GetMonitorInfoW,
    HBRUSH, HFONT, LOGFONTW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromPoint,
    MonitorFromWindow, OUT_DEFAULT_PRECIS, ReleaseDC, TEXTMETRICW,
};
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::Controls::SetWindowTheme;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, GetCursorPos, GetWindowRect, HICON, ICON_BIG, ICON_SMALL, IDI_APPLICATION,
    LoadIconW, SPI_GETHIGHCONTRAST, SendMessageW, SystemParametersInfoW, WM_SETICON,
};

use super::to_wide;

pub(crate) const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

pub(crate) const CLR_NOTICE_TEXT: u32 = rgb(130, 60, 0);
pub(crate) const CLR_NOTICE_BG: u32 = rgb(255, 248, 224);

pub(crate) fn scale_dpi(px: i32, dpi: u32) -> i32 {
    let safe_dpi = if dpi == 0 { 96 } else { dpi };
    (px * safe_dpi as i32 + 48) / 96
}

pub(crate) fn is_high_contrast() -> bool {
    let mut hc: HIGHCONTRASTW = unsafe { zeroed() };
    hc.cbSize = size_of::<HIGHCONTRASTW>() as u32;
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            hc.cbSize,
            (&raw mut hc).cast::<core::ffi::c_void>(),
            0,
        )
    };
    ok != 0 && (hc.dwFlags & HCF_HIGHCONTRASTON) != 0
}

unsafe extern "system" fn enum_font_callback(
    _lpelfe: *const LOGFONTW,
    _lpntme: *const TEXTMETRICW,
    _font_type: u32,
    l_param: LPARAM,
) -> i32 {
    if l_param != 0 {
        unsafe {
            *(l_param as *mut bool) = true;
        }
    }
    0
}

fn fill_logfont_face(lf: &mut LOGFONTW, face: &str) {
    let max_chars = lf.lfFaceName.len().saturating_sub(1);
    for (dst, unit) in lf.lfFaceName[..max_chars]
        .iter_mut()
        .zip(face.encode_utf16())
    {
        *dst = unit;
    }
}

fn font_exists(face: &str) -> bool {
    let hdc = unsafe { GetDC(null_mut()) };
    if hdc.is_null() {
        return false;
    }
    let mut lf: LOGFONTW = unsafe { zeroed() };
    lf.lfCharSet = DEFAULT_CHARSET;
    fill_logfont_face(&mut lf, face);
    let mut found = false;
    unsafe {
        EnumFontFamiliesExW(
            hdc,
            &raw const lf,
            Some(enum_font_callback),
            (&raw mut found) as LPARAM,
            0,
        );
        ReleaseDC(null_mut(), hdc);
    }
    found
}

fn create_font_by_face(face: &str, dpi: u32, weight: u32, px_96: i32) -> HFONT {
    let mut lf: LOGFONTW = unsafe { zeroed() };
    lf.lfHeight = -scale_dpi(px_96, dpi);
    lf.lfWeight = weight as i32;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
    lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
    lf.lfQuality = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = DEFAULT_PITCH;
    fill_logfont_face(&mut lf, face);
    unsafe { CreateFontIndirectW(&raw const lf) }
}

fn create_first_available_font(faces: &[&str], dpi: u32, weight: u32, px_96: i32) -> HFONT {
    for &face in faces {
        if font_exists(face) {
            let h_font = create_font_by_face(face, dpi, weight, px_96);
            if !h_font.is_null() {
                return h_font;
            }
        }
    }
    for &face in faces {
        let h_font = create_font_by_face(face, dpi, weight, px_96);
        if !h_font.is_null() {
            return h_font;
        }
    }
    null_mut()
}

pub(crate) fn create_ui_font(dpi: u32) -> HFONT {
    create_first_available_font(
        &["BIZ UDPゴシック", "Yu Gothic UI", "Segoe UI"],
        dpi,
        FW_NORMAL,
        15,
    )
}

pub(crate) fn create_bold_font(dpi: u32) -> HFONT {
    create_first_available_font(
        &["BIZ UDPゴシック", "Yu Gothic UI", "Segoe UI"],
        dpi,
        FW_BOLD,
        17,
    )
}

pub(crate) fn create_mono_font(dpi: u32) -> HFONT {
    create_first_available_font(
        &["BIZ UDゴシック", "Cascadia Mono", "Consolas"],
        dpi,
        FW_NORMAL,
        15,
    )
}

pub(crate) fn extract_app_icons() -> (HICON, HICON, bool) {
    let fallback = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
    (fallback, fallback, false)
}

pub(crate) struct ThemeResources {
    pub ui_font: HFONT,
    pub bold_font: HFONT,
    pub mono_font: HFONT,
    pub icon_large: HICON,
    pub icon_small: HICON,
    pub icons_owned: bool,
    pub notice_bg_brush: HBRUSH,
}

impl ThemeResources {
    pub fn new(dpi: u32) -> Self {
        let (icon_large, icon_small, icons_owned) = extract_app_icons();
        Self {
            ui_font: create_ui_font(dpi),
            bold_font: create_bold_font(dpi),
            mono_font: create_mono_font(dpi),
            icon_large,
            icon_small,
            icons_owned,
            notice_bg_brush: unsafe { CreateSolidBrush(CLR_NOTICE_BG) },
        }
    }

    /// 新フォントを生成して差し替え、再割り当て完了後に呼び出し側で破棄できるよう旧ハンドル群を返す。
    pub fn rebuild_fonts_for_dpi(&mut self, dpi: u32) -> (HFONT, HFONT, HFONT) {
        let old = (self.ui_font, self.bold_font, self.mono_font);
        self.ui_font = create_ui_font(dpi);
        self.bold_font = create_bold_font(dpi);
        self.mono_font = create_mono_font(dpi);
        old
    }

    pub fn delete_fonts(fonts: (HFONT, HFONT, HFONT)) {
        unsafe {
            if !fonts.0.is_null() {
                DeleteObject(fonts.0);
            }
            if !fonts.1.is_null() {
                DeleteObject(fonts.1);
            }
            if !fonts.2.is_null() {
                DeleteObject(fonts.2);
            }
        }
    }

    pub fn apply_icons_to_window(&self, hwnd: HWND) {
        unsafe {
            if !self.icon_large.is_null() {
                SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_BIG as usize,
                    self.icon_large as LPARAM,
                );
            }
            if !self.icon_small.is_null() {
                SendMessageW(
                    hwnd,
                    WM_SETICON,
                    ICON_SMALL as usize,
                    self.icon_small as LPARAM,
                );
            }
        }
    }
}

impl Drop for ThemeResources {
    fn drop(&mut self) {
        unsafe {
            if !self.ui_font.is_null() {
                DeleteObject(self.ui_font);
                self.ui_font = null_mut();
            }
            if !self.bold_font.is_null() {
                DeleteObject(self.bold_font);
                self.bold_font = null_mut();
            }
            if !self.mono_font.is_null() {
                DeleteObject(self.mono_font);
                self.mono_font = null_mut();
            }
            if !self.notice_bg_brush.is_null() {
                DeleteObject(self.notice_bg_brush);
                self.notice_bg_brush = null_mut();
            }
            if self.icons_owned {
                if !self.icon_large.is_null() {
                    DestroyIcon(self.icon_large);
                }
                if !self.icon_small.is_null() && self.icon_small != self.icon_large {
                    DestroyIcon(self.icon_small);
                }
                self.icon_large = null_mut();
                self.icon_small = null_mut();
                self.icons_owned = false;
            }
        }
    }
}

pub(crate) fn apply_listview_explorer_theme(hwnd_lv: HWND, high_contrast: bool) {
    if hwnd_lv.is_null() {
        return;
    }
    if high_contrast {
        let empty = to_wide("");
        unsafe {
            let _ = SetWindowTheme(hwnd_lv, empty.as_ptr(), empty.as_ptr());
        }
    } else {
        let explorer = to_wide("Explorer");
        unsafe {
            let _ = SetWindowTheme(hwnd_lv, explorer.as_ptr(), null());
        }
    }
}

pub(crate) fn apply_window_dwm_attributes(hwnd: HWND) {
    if hwnd.is_null() {
        return;
    }
    let corner = DWMWCP_ROUND;
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            (&raw const corner).cast(),
            size_of::<i32>() as u32,
        );
    }
}

pub(crate) fn center_rect_on_cursor_monitor(width: i32, height: i32) -> (i32, i32) {
    let mut pt: POINT = unsafe { zeroed() };
    unsafe {
        let _ = GetCursorPos(&raw mut pt);
    }
    let hmon = unsafe { MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST) };
    let mut mi: MONITORINFO = unsafe { zeroed() };
    mi.cbSize = size_of::<MONITORINFO>() as u32;
    if !hmon.is_null() && unsafe { GetMonitorInfoW(hmon, &raw mut mi) } != 0 {
        let wa = mi.rcWork;
        let x = wa.left + ((wa.right - wa.left - width) / 2).max(0);
        let y = wa.top + ((wa.bottom - wa.top - height) / 2).max(0);
        (x, y)
    } else {
        (100, 100)
    }
}

pub(crate) fn center_rect_on_parent(parent: HWND, width: i32, height: i32) -> (i32, i32) {
    if parent.is_null() {
        return center_rect_on_cursor_monitor(width, height);
    }
    let mut rc: RECT = unsafe { zeroed() };
    if unsafe { GetWindowRect(parent, &raw mut rc) } == 0 {
        return center_rect_on_cursor_monitor(width, height);
    }
    let raw_x = rc.left + ((rc.right - rc.left - width) / 2);
    let raw_y = rc.top + ((rc.bottom - rc.top - height) / 2);

    let hmon = unsafe { MonitorFromWindow(parent, MONITOR_DEFAULTTONEAREST) };
    let mut mi: MONITORINFO = unsafe { zeroed() };
    mi.cbSize = size_of::<MONITORINFO>() as u32;
    if !hmon.is_null() && unsafe { GetMonitorInfoW(hmon, &raw mut mi) } != 0 {
        let wa = mi.rcWork;
        let max_x = (wa.right - width).max(wa.left);
        let max_y = (wa.bottom - height).max(wa.top);
        (raw_x.clamp(wa.left, max_x), raw_y.clamp(wa.top, max_y))
    } else {
        (raw_x, raw_y)
    }
}
