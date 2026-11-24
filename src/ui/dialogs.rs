//! 安全なモーダルダイアログ群・クリップボードコピー・多重起動警告。

use std::cell::{Cell, RefCell};
use std::mem::{size_of, zeroed};
use std::path::PathBuf;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, LRESULT, TRUE, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{COLOR_BTNFACE, GetSysColorBrush, HFONT};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use windows_sys::Win32::System::SystemServices::{SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows_sys::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED, EM_SETLIMITTEXT};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus, VK_ESCAPE};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BN_CLICKED, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
    CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CBS_DROPDOWNLIST, CS_HREDRAW, CS_VREDRAW,
    CreateWindowExW, DC_HASDEFID, DM_GETDEFID, DefWindowProcW, DestroyWindow, DispatchMessageW,
    ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_NUMBER, ES_READONLY, GWLP_USERDATA,
    GetMessageW, GetWindowLongPtrW, IDC_ARROW, IDCANCEL, IDOK, IDYES, IsDialogMessageW,
    LB_ADDSTRING, LB_GETCURSEL, LB_RESETCONTENT, LBN_DBLCLK, LBS_NOINTEGRALHEIGHT, LBS_NOTIFY,
    LoadCursorW, MB_DEFBUTTON2, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO, MSG, MessageBoxW,
    PostQuitMessage, RegisterClassExW, SW_SHOW, SendMessageW, SetForegroundWindow,
    SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, WM_CLOSE, WM_COMMAND,
    WM_DESTROY, WM_KEYDOWN, WM_SETFONT, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_POPUP, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE, WS_VSCROLL,
};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use zerohop::app::coordinator::SessionLogReader;
use zerohop::domain::model::{MAX_MAX_MEMORY_MB, MIN_MAX_MEMORY_MB, PeerView, ThreadKey};
use zerohop::domain::session_log::SearchHit;
use zerohop::domain::validation::{ValidationError, validate_manual_peer_endpoint};
use zerohop::network::nic::{NicCandidate, discover_ipv4_nics};
use zerohop::storage::config::LocalConfig;
use zerohop::storage::paths::AppPaths;

use super::a11y::set_cue_banner;
use super::theme::{ThemeResources, apply_window_dwm_attributes, center_rect_on_parent, scale_dpi};
use super::{
    APP_NAME, APP_VERSION, format_bytes_human, format_unix_datetime, normalize_crlf,
    read_window_text, read_window_text_zeroizing, to_wide,
};

const MODAL_CLASS_NAME: &str = "ZeroHopModalDialogClass";

const IDC_DLG_DETAIL_META: usize = 4101;
const IDC_DLG_DETAIL_BODY: usize = 4102;
const IDC_DLG_DETAIL_COPY: usize = 4103;
const IDC_DLG_DETAIL_RETRY: usize = 4104;
const IDC_DLG_DETAIL_STATUS: usize = 4105;

const IDC_DLG_PEER_IP: usize = 4201;
const IDC_DLG_PEER_PORT: usize = 4202;
const IDC_DLG_PEER_ERR: usize = 4203;

const IDC_DLG_OPT_NIC: usize = 4301;
const IDC_DLG_OPT_UDP: usize = 4302;
const IDC_DLG_OPT_TCP: usize = 4303;
const IDC_DLG_OPT_MEM: usize = 4304;
const IDC_DLG_OPT_ERR: usize = 4305;
const IDC_DLG_OPT_AWAY: usize = 4306;
const IDC_DLG_OPT_SOUND_MASTER: usize = 4307;
const IDC_DLG_OPT_SOUND_LOGIN: usize = 4308;
const IDC_DLG_OPT_SOUND_PEER: usize = 4309;
const IDC_DLG_OPT_SOUND_MSG: usize = 4310;
const IDC_DLG_OPT_SEND_ENTER: usize = 4311;
const IDC_DLG_OPT_HIDE_PREVIEW: usize = 4312;

const IDC_DLG_INFO_BODY: usize = 4401;
const IDC_DLG_INFO_COPY: usize = 4402;
const IDC_DLG_INFO_STATUS: usize = 4403;

const IDC_DLG_SEARCH_QUERY: usize = 4501;
const IDC_DLG_SEARCH_CURRENT_ONLY: usize = 4502;
const IDC_DLG_SEARCH_RUN: usize = 4503;
const IDC_DLG_SEARCH_LIST: usize = 4504;
const IDC_DLG_SEARCH_JUMP: usize = 4505;
const IDC_DLG_SEARCH_STATUS: usize = 4506;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DetailDialogInput {
    pub sender_name: String,
    pub time_text: String,
    pub status_text: String,
    pub body: String,
    #[zeroize(skip)]
    pub can_retry: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetailDialogAction {
    Closed,
    Retry,
}

pub(crate) fn copy_text_to_clipboard(hwnd: HWND, text: &str) -> bool {
    let mut wide = to_wide(text);
    let bytes = wide.len() * size_of::<u16>();
    unsafe {
        let hmem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if hmem.is_null() {
            wide.zeroize();
            return false;
        }
        let ptr = GlobalLock(hmem) as *mut u16;
        if ptr.is_null() {
            wide.zeroize();
            GlobalFree(hmem);
            return false;
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
        wide.zeroize();
        GlobalUnlock(hmem);

        if OpenClipboard(hwnd) == 0 {
            GlobalFree(hmem);
            return false;
        }
        EmptyClipboard();
        let res = SetClipboardData(u32::from(CF_UNICODETEXT), hmem as HANDLE);
        CloseClipboard();
        if res.is_null() {
            GlobalFree(hmem);
            return false;
        }
        true
    }
}

pub(crate) fn show_single_instance_warning() {
    let title = to_wide("ZeroHop - 多重起動の確認");
    let msg = to_wide(
        "ZeroHop はすでに起動しています。\n\
         同一 PC 上で複数起動してテストする場合は --multi オプションを指定してください。",
    );
    unsafe {
        MessageBoxW(
            null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONWARNING,
        );
    }
}

enum ModalSignal {
    Continue,
    Close,
}

trait ModalHandler {
    fn on_command(&mut self, dlg: HWND, id: usize, code: u32) -> ModalSignal;
    fn default_button_id(&self) -> i32 {
        IDOK
    }
}

struct ModalEnvelope<H: ModalHandler> {
    done: Cell<bool>,
    handler: RefCell<H>,
}

unsafe extern "system" fn modal_wnd_proc<H: ModalHandler>(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const ModalEnvelope<H>;
        match msg {
            DM_GETDEFID => {
                if !ptr.is_null()
                    && let Ok(h) = (*ptr).handler.try_borrow()
                {
                    let def_id = h.default_button_id();
                    return ((DC_HASDEFID as isize) << 16) | (def_id as isize & 0xFFFF);
                }
                0
            }
            WM_COMMAND => {
                if !ptr.is_null() {
                    let id = wparam & 0xFFFF;
                    let code = ((wparam >> 16) & 0xFFFF) as u32;
                    let env = &*ptr;
                    if let Ok(mut h) = env.handler.try_borrow_mut()
                        && matches!(h.on_command(hwnd, id, code), ModalSignal::Close)
                    {
                        env.done.set(true);
                        return 0;
                    }
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_CLOSE => {
                if !ptr.is_null() {
                    (*ptr).done.set(true);
                }
                0
            }
            WM_DESTROY => {
                if !ptr.is_null() {
                    (*ptr).done.set(true);
                }
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }));
    res.unwrap_or(0)
}

fn ensure_modal_class_registered<H: ModalHandler>(hinst: HANDLE) -> Vec<u16> {
    // テンプレート型ごとに異なる WndProc アドレスが生成されるため、型名ベースの一意クラス名で登録する
    let suffix = core::any::type_name::<H>().bytes().fold(0u64, |acc, b| {
        acc.wrapping_mul(131).wrapping_add(u64::from(b))
    });
    let cls_name = format!("{MODAL_CLASS_NAME}_{suffix:016x}");
    let cls_w = to_wide(&cls_name);
    let mut wc: WNDCLASSEXW = unsafe { zeroed() };
    wc.cbSize = size_of::<WNDCLASSEXW>() as u32;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = Some(modal_wnd_proc::<H>);
    wc.hInstance = hinst;
    wc.hCursor = unsafe { LoadCursorW(null_mut(), IDC_ARROW) };
    wc.hbrBackground = unsafe { GetSysColorBrush(COLOR_BTNFACE) };
    wc.lpszClassName = cls_w.as_ptr();
    unsafe {
        let _ = RegisterClassExW(&raw const wc);
    }
    cls_w
}

fn run_modal_dialog<H: ModalHandler>(
    parent: HWND,
    title: &str,
    width_96: i32,
    height_96: i32,
    dpi: u32,
    build: impl FnOnce(HWND, HANDLE, HFONT, HFONT) -> (H, HWND),
) -> H {
    let hinst = unsafe { GetModuleHandleW(null()) };
    let cls_w = ensure_modal_class_registered::<H>(hinst);

    let width = scale_dpi(width_96, dpi);
    let height = scale_dpi(height_96, dpi);
    let (x, y) = center_rect_on_parent(parent, width, height);
    let title_w = to_wide(title);

    let dlg = unsafe {
        CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
            cls_w.as_ptr(),
            title_w.as_ptr(),
            WS_POPUP | WS_CAPTION | WS_SYSMENU,
            x,
            y,
            width,
            height,
            parent,
            null_mut(),
            hinst,
            null_mut(),
        )
    };

    let theme = ThemeResources::new(dpi);
    let (handler, initial_focus) = build(dlg, hinst, theme.ui_font, theme.mono_font);
    if dlg.is_null() {
        return handler;
    }

    apply_window_dwm_attributes(dlg);

    let env = ModalEnvelope {
        done: Cell::new(false),
        handler: RefCell::new(handler),
    };

    unsafe {
        SetWindowLongPtrW(dlg, GWLP_USERDATA, (&raw const env) as isize);
        if !parent.is_null() {
            EnableWindow(parent, 0);
        }
        ShowWindow(dlg, SW_SHOW);
        if !initial_focus.is_null() {
            SetFocus(initial_focus);
        }

        let mut msg: MSG = zeroed();
        while !env.done.get() {
            let gm = GetMessageW(&raw mut msg, null_mut(), 0, 0);
            if gm == 0 {
                PostQuitMessage(msg.wParam as i32);
                break;
            }
            if gm < 0 {
                break;
            }
            if msg.message == WM_KEYDOWN && msg.wParam == usize::from(VK_ESCAPE) {
                env.done.set(true);
                break;
            }
            if IsDialogMessageW(dlg, &raw const msg) == 0 {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
        }

        // Win32 モーダル安全破棄順序（背面落ち・ダングリングポインタ防止）
        if !parent.is_null() {
            EnableWindow(parent, TRUE);
        }
        SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
        DestroyWindow(dlg);
        if !parent.is_null() {
            SetForegroundWindow(parent);
        }
    }

    env.handler.into_inner()
}

#[allow(clippy::too_many_arguments)]
fn create_static(
    parent: HWND,
    hinst: HANDLE,
    font: HFONT,
    id: usize,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
) -> HWND {
    let cls = to_wide("STATIC");
    let txt = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            cls.as_ptr(),
            txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            x,
            y,
            w,
            h,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        hwnd
    }
}

#[allow(clippy::too_many_arguments)]
fn create_edit(
    parent: HWND,
    hinst: HANDLE,
    font: HFONT,
    id: usize,
    text: &str,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
) -> HWND {
    let cls = to_wide("EDIT");
    let txt = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            cls.as_ptr(),
            txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | style,
            x,
            y,
            w,
            h,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        hwnd
    }
}

#[allow(clippy::too_many_arguments)]
fn create_button(
    parent: HWND,
    hinst: HANDLE,
    font: HFONT,
    id: usize,
    text: &str,
    is_default: bool,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
) -> HWND {
    let cls = to_wide("BUTTON");
    let txt = to_wide(text);
    let bs = if is_default {
        BS_DEFPUSHBUTTON as u32
    } else {
        BS_PUSHBUTTON as u32
    };
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            cls.as_ptr(),
            txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | bs,
            x,
            y,
            w,
            h,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        hwnd
    }
}

// 1. ログアウト／終了確認ダイアログ（初期フォーカスはキャンセル側）
struct ConfirmHandler {
    confirmed: bool,
}

impl ModalHandler for ConfirmHandler {
    fn default_button_id(&self) -> i32 {
        IDCANCEL
    }

    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDOK as usize {
            self.confirmed = true;
            ModalSignal::Close
        } else if id == IDCANCEL as usize {
            self.confirmed = false;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn confirm_logout_or_exit(parent: HWND, is_exit: bool, dpi: u32) -> bool {
    let (title, body, ok_label) = if is_exit {
        (
            "終了の確認 - ZeroHop",
            "終了すると、現在の会話内容、暗号鍵、および一時キャッシュはすべて消去され復元できません。\r\nよろしいですか？",
            "全消去して終了(&Y)",
        )
    } else {
        (
            "ログアウトの確認 - ZeroHop",
            "ログアウトすると、現在の会話内容、暗号鍵、および一時キャッシュはすべて消去され復元できません。\r\nよろしいですか？",
            "ログアウトして全消去(&Y)",
        )
    };

    let res = run_modal_dialog(parent, title, 470, 175, dpi, |dlg, hinst, ui_font, _| {
        let s = |v| scale_dpi(v, dpi);
        let _lbl = create_static(dlg, hinst, ui_font, 0, body, s(16), s(16), s(424), s(56));
        let _btn_ok = create_button(
            dlg,
            hinst,
            ui_font,
            IDOK as usize,
            ok_label,
            false,
            s(128),
            s(88),
            s(188),
            s(30),
        );
        let btn_cancel = create_button(
            dlg,
            hinst,
            ui_font,
            IDCANCEL as usize,
            "キャンセル(&N)",
            true,
            s(326),
            s(88),
            s(114),
            s(30),
        );
        (ConfirmHandler { confirmed: false }, btn_cancel)
    });
    res.confirmed
}

// 2. メッセージ全文詳細モーダル（選択行 Enter で起動・コピー・再送・Esc 復帰）
struct DetailHandler {
    body: Zeroizing<String>,
    can_retry: bool,
    hwnd_status: HWND,
    action: DetailDialogAction,
}

impl ModalHandler for DetailHandler {
    fn default_button_id(&self) -> i32 {
        IDCANCEL
    }

    fn on_command(&mut self, dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDC_DLG_DETAIL_COPY {
            let msg = if copy_text_to_clipboard(dlg, &self.body) {
                "メッセージ本文をクリップボードへコピーしました。"
            } else {
                "クリップボードへのコピーに失敗しました。"
            };
            let w = to_wide(msg);
            unsafe {
                SetWindowTextW(self.hwnd_status, w.as_ptr());
            }
            ModalSignal::Continue
        } else if id == IDC_DLG_DETAIL_RETRY && self.can_retry {
            self.action = DetailDialogAction::Retry;
            ModalSignal::Close
        } else if id == IDCANCEL as usize {
            self.action = DetailDialogAction::Closed;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_message_detail_dialog(
    parent: HWND,
    detail: &DetailDialogInput,
    dpi: u32,
) -> DetailDialogAction {
    let meta = Zeroizing::new(format!(
        "送信者: {}  |  時刻: {}  |  状態: {}",
        detail.sender_name, detail.time_text, detail.status_text
    ));
    let body_crlf = Zeroizing::new(normalize_crlf(&detail.body));
    let body_clone = Zeroizing::new(detail.body.clone());
    let can_retry = detail.can_retry;

    let res = run_modal_dialog(
        parent,
        "メッセージ全文詳細 - ZeroHop",
        600,
        410,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _meta_lbl = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_META,
                &meta,
                s(16),
                s(12),
                s(552),
                s(22),
            );
            let hwnd_edit = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_BODY,
                &body_crlf,
                WS_BORDER
                    | WS_VSCROLL
                    | (ES_MULTILINE as u32)
                    | (ES_AUTOVSCROLL as u32)
                    | (ES_READONLY as u32),
                s(16),
                s(40),
                s(552),
                s(250),
            );
            unsafe {
                SendMessageW(hwnd_edit, EM_SETLIMITTEXT, 0x7FFF_FFFE, 0);
            }
            let hwnd_status = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_STATUS,
                "Esc キーまたは「閉じる」で会話一覧の選択行へ戻ります。",
                s(16),
                s(298),
                s(552),
                s(20),
            );
            let _btn_copy = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_COPY,
                "本文をコピー(&C)",
                false,
                s(16),
                s(326),
                s(146),
                s(30),
            );
            let btn_retry = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_RETRY,
                "再送(&R)",
                false,
                s(174),
                s(326),
                s(104),
                s(30),
            );
            if !can_retry {
                unsafe {
                    EnableWindow(btn_retry, 0);
                }
            }
            let _btn_close = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "閉じる(&X)",
                true,
                s(458),
                s(326),
                s(110),
                s(30),
            );
            (
                DetailHandler {
                    body: body_clone,
                    can_retry,
                    hwnd_status,
                    action: DetailDialogAction::Closed,
                },
                hwnd_edit,
            )
        },
    );
    res.action
}

// 3. 手動ピア追加ダイアログ (Ctrl+M)
struct ManualPeerHandler {
    hwnd_ip: HWND,
    hwnd_port: HWND,
    hwnd_err: HWND,
    result: Option<(String, u16)>,
}

impl ModalHandler for ManualPeerHandler {
    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDOK as usize {
            let ip_text = read_window_text(self.hwnd_ip);
            let port_text = read_window_text(self.hwnd_port);
            let parsed_port = port_text.trim().parse::<u16>().unwrap_or(0);
            match validate_manual_peer_endpoint(&ip_text, parsed_port) {
                Ok((ip, port)) => {
                    self.result = Some((ip.to_string(), port));
                    ModalSignal::Close
                }
                Err(err) => {
                    let msg = to_wide(&err.to_string());
                    let focus_target = if matches!(err, ValidationError::InvalidPort) {
                        self.hwnd_port
                    } else {
                        self.hwnd_ip
                    };
                    unsafe {
                        SetWindowTextW(self.hwnd_err, msg.as_ptr());
                        SetFocus(focus_target);
                    }
                    ModalSignal::Continue
                }
            }
        } else if id == IDCANCEL as usize {
            self.result = None;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_add_manual_peer_dialog(
    parent: HWND,
    default_port: u16,
    dpi: u32,
) -> Option<(String, u16)> {
    let port_default = default_port.to_string();
    let res = run_modal_dialog(
        parent,
        "手動ピア追加 - ZeroHop",
        430,
        225,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl_ip = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "相手のIPアドレス(&I):",
                s(16),
                s(14),
                s(380),
                s(20),
            );
            let hwnd_ip = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_IP,
                "",
                ES_AUTOHSCROLL as u32,
                s(16),
                s(36),
                s(380),
                s(26),
            );
            set_cue_banner(hwnd_ip, "例: 192.168.1.50 または 127.0.0.1");

            let _lbl_port = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "相手のTCP待受ポート番号(&P):",
                s(16),
                s(72),
                s(380),
                s(20),
            );
            let hwnd_port = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_PORT,
                &port_default,
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(94),
                s(140),
                s(26),
            );
            let hwnd_err = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_ERR,
                "",
                s(16),
                s(126),
                s(380),
                s(20),
            );
            let _btn_ok = create_button(
                dlg,
                hinst,
                ui_font,
                IDOK as usize,
                "接続して追加(&A)",
                true,
                s(160),
                s(150),
                s(132),
                s(30),
            );
            let _btn_cancel = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "キャンセル",
                false,
                s(302),
                s(150),
                s(94),
                s(30),
            );
            (
                ManualPeerHandler {
                    hwnd_ip,
                    hwnd_port,
                    hwnd_err,
                    result: None,
                },
                hwnd_ip,
            )
        },
    );
    res.result
}

// 4. オプション設定ダイアログ（NIC・ポート・メモリ上限・効果音・通知・送信キー・自動離席）
#[allow(clippy::too_many_arguments)]
fn create_checkbox(
    parent: HWND,
    hinst: HANDLE,
    font: HFONT,
    id: usize,
    text: &str,
    checked: bool,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
) -> HWND {
    let cls = to_wide("BUTTON");
    let txt_w = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            cls.as_ptr(),
            txt_w.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_AUTOCHECKBOX as u32),
            x,
            y,
            w,
            h,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        SendMessageW(
            hwnd,
            BM_SETCHECK,
            if checked { BST_CHECKED } else { BST_UNCHECKED } as usize,
            0,
        );
        hwnd
    }
}

fn is_checked(hwnd: HWND) -> bool {
    unsafe { SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED as isize }
}

struct OptionsHandler {
    current_cfg: LocalConfig,
    nics: Vec<NicCandidate>,
    hwnd_nic: HWND,
    hwnd_udp: HWND,
    hwnd_tcp: HWND,
    hwnd_mem: HWND,
    hwnd_away: HWND,
    hwnd_sound_master: HWND,
    hwnd_sound_login: HWND,
    hwnd_sound_peer: HWND,
    hwnd_sound_msg: HWND,
    hwnd_send_enter: HWND,
    hwnd_hide_preview: HWND,
    hwnd_err: HWND,
    result: Option<LocalConfig>,
}

impl ModalHandler for OptionsHandler {
    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDOK as usize {
            let udp_str = read_window_text(self.hwnd_udp);
            let tcp_str = read_window_text(self.hwnd_tcp);
            let mem_str = read_window_text(self.hwnd_mem);

            let Ok(udp_port) = udp_str.trim().parse::<u16>() else {
                let msg = to_wide("UDPポートは 1〜65535 の数値で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_udp);
                }
                return ModalSignal::Continue;
            };
            if udp_port == 0 {
                let msg = to_wide("UDPポートは 1〜65535 を指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_udp);
                }
                return ModalSignal::Continue;
            }
            let Ok(tcp_port) = tcp_str.trim().parse::<u16>() else {
                let msg = to_wide("TCPポートは 1〜65535 の数値で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_tcp);
                }
                return ModalSignal::Continue;
            };
            if tcp_port == 0 {
                let msg = to_wide("TCPポートは 1〜65535 を指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_tcp);
                }
                return ModalSignal::Continue;
            }
            let Ok(mem_mb) = mem_str.trim().parse::<u16>() else {
                let msg = to_wide("会話メモリ上限は 4〜32 MiB の数値で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_mem);
                }
                return ModalSignal::Continue;
            };
            if !(MIN_MAX_MEMORY_MB..=MAX_MAX_MEMORY_MB).contains(&mem_mb) {
                let msg = to_wide("会話メモリ上限は 4〜32 MiB の範囲で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_mem);
                }
                return ModalSignal::Continue;
            }

            let away_str = read_window_text(self.hwnd_away);
            let Ok(away_mins) = away_str.trim().parse::<u16>() else {
                let msg = to_wide("自動離席時間は 0〜60 分の数値で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_away);
                }
                return ModalSignal::Continue;
            };
            if away_mins > 60 {
                let msg = to_wide("自動離席時間は 0〜60 分の範囲で指定してください。");
                unsafe {
                    SetWindowTextW(self.hwnd_err, msg.as_ptr());
                    SetFocus(self.hwnd_away);
                }
                return ModalSignal::Continue;
            }

            let sel = unsafe { SendMessageW(self.hwnd_nic, CB_GETCURSEL, 0, 0) };
            let preferred_nic_ip = if sel > 0 {
                self.nics.get((sel as usize) - 1).map(|n| n.ip.to_string())
            } else {
                None
            };

            let mut next = self.current_cfg.clone();
            next.udp_port = udp_port;
            next.tcp_port = tcp_port;
            next.max_memory_mb = mem_mb;
            next.preferred_nic_ip = preferred_nic_ip;
            next.auto_away_minutes = away_mins;
            next.sound_enabled = is_checked(self.hwnd_sound_master);
            next.sound_on_login_logout = is_checked(self.hwnd_sound_login);
            next.sound_on_peer_presence = is_checked(self.hwnd_sound_peer);
            next.sound_on_message = is_checked(self.hwnd_sound_msg);
            next.send_on_enter = is_checked(self.hwnd_send_enter);
            next.hide_notification_preview = is_checked(self.hwnd_hide_preview);
            next.sanitize();
            self.result = Some(next);
            ModalSignal::Close
        } else if id == IDCANCEL as usize {
            self.result = None;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_options_dialog(
    parent: HWND,
    current_cfg: &LocalConfig,
    paths: &AppPaths,
    dpi: u32,
) -> Option<LocalConfig> {
    let nics = discover_ipv4_nics();
    let writable = paths.is_base_dir_writable();
    let persist_note = if writable {
        "設定は config.json に保存されます（表示名・パスワード・履歴は保存しません）。"
    } else {
        "読み取り専用フォルダのため設定ファイルは書き込まれず、このセッションのみ反映されます。"
    };
    let cfg_clone = current_cfg.clone();

    let res = run_modal_dialog(
        parent,
        "オプション設定 - ZeroHop",
        520,
        520,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl_nic = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "使用ネットワークアダプタ (NIC)(&N):",
                s(16),
                s(14),
                s(452),
                s(20),
            );
            let cb_cls = to_wide("COMBOBOX");
            let hwnd_nic = unsafe {
                CreateWindowExW(
                    0,
                    cb_cls.as_ptr(),
                    null(),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | (CBS_DROPDOWNLIST as u32),
                    s(16),
                    s(36),
                    s(452),
                    s(200),
                    dlg,
                    IDC_DLG_OPT_NIC as _,
                    hinst,
                    null_mut(),
                )
            };
            unsafe {
                SendMessageW(hwnd_nic, WM_SETFONT, ui_font as usize, 1);
                let auto_w = to_wide("自動選択（物理NIC優先）");
                SendMessageW(hwnd_nic, CB_ADDSTRING, 0, auto_w.as_ptr() as LPARAM);
                let mut selected_idx: usize = 0;
                for (i, nic) in nics.iter().enumerate() {
                    let vtag = if nic.is_virtual { " [仮想]" } else { "" };
                    let label = format!("{} ({}){vtag}", nic.friendly_name, nic.ip);
                    let w = to_wide(&label);
                    SendMessageW(hwnd_nic, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
                    if cfg_clone.preferred_nic_ip.as_deref() == Some(&nic.ip.to_string()) {
                        selected_idx = i + 1;
                    }
                }
                SendMessageW(hwnd_nic, CB_SETCURSEL, selected_idx, 0);
            }

            let _lbl_udp = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "UDP 検出ポート(&U):",
                s(16),
                s(74),
                s(210),
                s(20),
            );
            let hwnd_udp = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_UDP,
                &cfg_clone.udp_port.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(96),
                s(160),
                s(26),
            );

            let _lbl_tcp = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "TCP 通信ポート(&T):",
                s(240),
                s(74),
                s(210),
                s(20),
            );
            let hwnd_tcp = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_TCP,
                &cfg_clone.tcp_port.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(240),
                s(96),
                s(160),
                s(26),
            );

            let _lbl_mem = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "会話メモリ上限 (4〜32 MiB)(&M):",
                s(16),
                s(134),
                s(220),
                s(20),
            );
            let hwnd_mem = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_MEM,
                &cfg_clone.max_memory_mb.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(156),
                s(120),
                s(26),
            );

            let _lbl_away = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "自動離席 (分, 0で無効)(&A):",
                s(240),
                s(134),
                s(240),
                s(20),
            );
            let hwnd_away = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_AWAY,
                &cfg_clone.auto_away_minutes.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(240),
                s(156),
                s(120),
                s(26),
            );

            let hwnd_sound_master = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_MASTER,
                "効果音・通知音を有効にする(&S)",
                cfg_clone.sound_enabled,
                s(16),
                s(194),
                s(468),
                s(22),
            );
            let hwnd_sound_login = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_LOGIN,
                "ログイン・ログアウト／終了音を鳴らす",
                cfg_clone.sound_on_login_logout,
                s(34),
                s(220),
                s(450),
                s(22),
            );
            let hwnd_sound_peer = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_PEER,
                "他ピアの参加・退出音を鳴らす",
                cfg_clone.sound_on_peer_presence,
                s(34),
                s(246),
                s(450),
                s(22),
            );
            let hwnd_sound_msg = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_MSG,
                "新着メッセージ通知音を鳴らす",
                cfg_clone.sound_on_message,
                s(34),
                s(272),
                s(450),
                s(22),
            );
            let hwnd_send_enter = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SEND_ENTER,
                "Enterキーで送信する (Shift+Enterで改行)(&E)",
                cfg_clone.send_on_enter,
                s(16),
                s(302),
                s(468),
                s(22),
            );
            let hwnd_hide_preview = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_HIDE_PREVIEW,
                "新着通知で送信者・本文プレビューを隠す(&P)",
                cfg_clone.hide_notification_preview,
                s(16),
                s(328),
                s(468),
                s(22),
            );

            let _lbl_note = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                persist_note,
                s(16),
                s(362),
                s(472),
                s(34),
            );
            let hwnd_err = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_ERR,
                "",
                s(16),
                s(402),
                s(472),
                s(20),
            );

            let _btn_ok = create_button(
                dlg,
                hinst,
                ui_font,
                IDOK as usize,
                "保存(&O)",
                true,
                s(278),
                s(436),
                s(100),
                s(30),
            );
            let _btn_cancel = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "キャンセル",
                false,
                s(388),
                s(436),
                s(100),
                s(30),
            );

            (
                OptionsHandler {
                    current_cfg: cfg_clone,
                    nics,
                    hwnd_nic,
                    hwnd_udp,
                    hwnd_tcp,
                    hwnd_mem,
                    hwnd_away,
                    hwnd_sound_master,
                    hwnd_sound_login,
                    hwnd_sound_peer,
                    hwnd_sound_msg,
                    hwnd_send_enter,
                    hwnd_hide_preview,
                    hwnd_err,
                    result: None,
                },
                hwnd_nic,
            )
        },
    );
    res.result
}

// 5. 情報表示用モーダル共通（通信情報・ショートカット一覧・バージョン情報）
struct ReadOnlyInfoHandler {
    text: String,
    hwnd_status: HWND,
    allow_copy: bool,
}

impl ModalHandler for ReadOnlyInfoHandler {
    fn default_button_id(&self) -> i32 {
        IDCANCEL
    }

    fn on_command(&mut self, dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if self.allow_copy && id == IDC_DLG_INFO_COPY {
            let msg = if copy_text_to_clipboard(dlg, &self.text) {
                "情報をクリップボードへコピーしました。"
            } else {
                "コピーに失敗しました。"
            };
            let w = to_wide(msg);
            unsafe { SetWindowTextW(self.hwnd_status, w.as_ptr()) };
            ModalSignal::Continue
        } else if id == IDCANCEL as usize {
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn show_readonly_info_modal(
    parent: HWND,
    title: &str,
    text: &str,
    allow_copy: bool,
    use_mono: bool,
    width_96: i32,
    height_96: i32,
    dpi: u32,
) {
    let text_owned = text.to_string();
    let text_crlf = normalize_crlf(text);
    let _ = run_modal_dialog(
        parent,
        title,
        width_96,
        height_96,
        dpi,
        |dlg, hinst, ui_font, mono_font| {
            let s = |v| scale_dpi(v, dpi);
            let body_font = if use_mono { mono_font } else { ui_font };
            let hwnd_edit = create_edit(
                dlg,
                hinst,
                body_font,
                IDC_DLG_INFO_BODY,
                &text_crlf,
                WS_BORDER
                    | WS_VSCROLL
                    | (ES_MULTILINE as u32)
                    | (ES_AUTOVSCROLL as u32)
                    | (ES_READONLY as u32),
                s(16),
                s(16),
                s(width_96 - 48),
                s(height_96 - 118),
            );
            unsafe {
                SendMessageW(hwnd_edit, EM_SETLIMITTEXT, 0x7FFF_FFFE, 0);
            }
            let hwnd_status = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_INFO_STATUS,
                "",
                s(16),
                s(height_96 - 96),
                s(width_96 - 290),
                s(22),
            );
            if allow_copy {
                let _btn_copy = create_button(
                    dlg,
                    hinst,
                    ui_font,
                    IDC_DLG_INFO_COPY,
                    "情報をコピー(&C)",
                    false,
                    s(16),
                    s(height_96 - 72),
                    s(146),
                    s(30),
                );
            }
            let _btn_close = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "閉じる(&X)",
                true,
                s(width_96 - 142),
                s(height_96 - 72),
                s(110),
                s(30),
            );
            (
                ReadOnlyInfoHandler {
                    text: text_owned,
                    hwnd_status,
                    allow_copy,
                },
                hwnd_edit,
            )
        },
    );
}

pub(crate) fn show_connection_info_dialog(parent: HWND, info_text: &str, dpi: u32) {
    show_readonly_info_modal(
        parent,
        "ルーム確認コード・通信情報 - ZeroHop",
        info_text,
        true,
        true,
        580,
        400,
        dpi,
    );
}

pub(crate) fn show_shortcuts_dialog(parent: HWND, dpi: u32) {
    let text = "\
[グローバル・メニュー操作]\n\
  Alt + A / E / T / H  : メニューバー各項目を開く\n\
  F6 / Shift+F6        : 接続先リスト / 会話一覧 / メッセージ入力欄を巡回移動\n\
  Ctrl + F             : セッション内メッセージ検索\n\
  Ctrl + L             : ワンキー画面ロック（会話・ピア一覧を即時遮蔽）\n\
  Ctrl + M             : 手動ピア追加（IP・ポート指定接続）\n\
  F5                   : ネットワーク再検出（NIC・ソケット再確認）\n\
  Ctrl + Shift + L     : ログアウト確認ダイアログ（全消去）\n\
  Ctrl + Shift + Del   : 現在表示中の会話表示をクリア\n\
  Alt + F4             : 終了（ログイン中は確認後に全消去して終了）\n\
\n\
[ログイン・ロック画面]\n\
  Enter                : ログインまたは画面ロック解除を実行\n\
  Tab / Shift + Tab    : 入力欄・表示切替・ボタンを移動\n\
\n\
[会話一覧・入力欄]\n\
  上下矢印キー         : 会話メッセージ行または接続先を選択\n\
  Enter（会話一覧上）  : 選択メッセージの全文詳細ダイアログを開く（コピー・再送可）\n\
  Esc（詳細画面上）    : 詳細ダイアログを閉じて直前選択行へフォーカス復帰\n\
  Ctrl + Enter（入力欄）: 既定設定時のメッセージ送信（Enter のみは改行）\n\
  Enter（入力欄）      : 「Enterキーで送信」有効時の送信（Shift+Enter で改行、IME変換中は非送信）\n\
  Ctrl + A（入力欄）   : 入力テキストを全選択";
    show_readonly_info_modal(
        parent,
        "キーボードショートカット一覧 - ZeroHop",
        text,
        false,
        true,
        640,
        460,
        dpi,
    );
}

// 6. セッション内検索モーダル (Phase 2 Step 2-3)
pub(crate) struct SearchDialogResult {
    pub last_query: Zeroizing<String>,
    pub jump_target: Option<(ThreadKey, usize)>,
}

struct SearchHandler {
    log_reader: SessionLogReader,
    active_thread: ThreadKey,
    peer_names: Vec<(String, String)>,
    hwnd_query: HWND,
    hwnd_current_only: HWND,
    hwnd_list: HWND,
    hwnd_status: HWND,
    hits: Vec<SearchHit>,
    last_query: Zeroizing<String>,
    jump_target: Option<(ThreadKey, usize)>,
}

impl SearchHandler {
    fn thread_label(&self, thread: &ThreadKey) -> String {
        match thread {
            ThreadKey::Broadcast => "全体チャット".to_string(),
            ThreadKey::Peer(pid) => self
                .peer_names
                .iter()
                .find(|(id, _)| id == pid)
                .map_or_else(|| pid.clone(), |(_, name)| name.clone()),
        }
    }

    fn execute_search(&mut self) {
        let query = read_window_text_zeroizing(self.hwnd_query);
        self.last_query = Zeroizing::new(query.to_string());
        let current_only = is_checked(self.hwnd_current_only);
        let filter = if current_only {
            Some(&self.active_thread)
        } else {
            None
        };

        for mut old in self.hits.drain(..) {
            old.zeroize();
        }
        self.hits = self.log_reader.search(filter, &query, 200);

        unsafe {
            SendMessageW(self.hwnd_list, LB_RESETCONTENT, 0, 0);
            for hit in &self.hits {
                let thread_lbl = self.thread_label(&hit.thread);
                let time_lbl = format_unix_datetime(hit.timestamp);
                let line = format!(
                    "[{thread_lbl}] {time_lbl} {}: {}",
                    hit.sender_name, hit.preview
                );
                let line_w = to_wide(&line);
                SendMessageW(self.hwnd_list, LB_ADDSTRING, 0, line_w.as_ptr() as LPARAM);
            }
            let status_msg = if query.trim().is_empty() {
                "検索キーワードを入力してください。".to_string()
            } else if self.hits.is_empty() {
                "一致するメッセージは見つかりませんでした。".to_string()
            } else {
                format!(
                    "{} 件見つかりました（上下キーまたはダブルクリックで移動）。",
                    self.hits.len()
                )
            };
            let status_w = to_wide(&status_msg);
            SetWindowTextW(self.hwnd_status, status_w.as_ptr());
        }
    }

    fn select_current_and_close(&mut self) -> ModalSignal {
        let idx = unsafe { SendMessageW(self.hwnd_list, LB_GETCURSEL, 0, 0) };
        if idx >= 0
            && let Some(hit) = self.hits.get(idx as usize)
        {
            self.jump_target = Some((hit.thread.clone(), hit.index));
            return ModalSignal::Close;
        }
        let msg = to_wide("移動先の検索結果を選択してください。");
        unsafe { SetWindowTextW(self.hwnd_status, msg.as_ptr()) };
        ModalSignal::Continue
    }
}

impl Drop for SearchHandler {
    fn drop(&mut self) {
        for mut h in self.hits.drain(..) {
            h.zeroize();
        }
    }
}

impl ModalHandler for SearchHandler {
    fn default_button_id(&self) -> i32 {
        IDC_DLG_SEARCH_RUN as i32
    }

    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if id == IDC_DLG_SEARCH_LIST && code == LBN_DBLCLK {
            return self.select_current_and_close();
        }
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDC_DLG_SEARCH_RUN || id == IDOK as usize {
            self.execute_search();
            ModalSignal::Continue
        } else if id == IDC_DLG_SEARCH_JUMP {
            self.select_current_and_close()
        } else if id == IDCANCEL as usize {
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_search_dialog(
    parent: HWND,
    log_reader: SessionLogReader,
    active_thread: ThreadKey,
    peers: &[PeerView],
    initial_query: &str,
    dpi: u32,
) -> SearchDialogResult {
    let peer_names: Vec<(String, String)> = peers
        .iter()
        .map(|p| (p.peer_id.clone(), p.display_name.clone()))
        .collect();
    let initial_q = initial_query.to_string();

    let mut res = run_modal_dialog(
        parent,
        "セッション内メッセージ検索 - ZeroHop",
        620,
        430,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "検索キーワード(&K):",
                s(16),
                s(14),
                s(572),
                s(20),
            );
            let hwnd_query = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_QUERY,
                &initial_q,
                ES_AUTOHSCROLL as u32,
                s(16),
                s(38),
                s(460),
                s(26),
            );
            set_cue_banner(hwnd_query, "キーワード（送信者名または本文）");

            let _btn_run = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_RUN,
                "検索(&S)",
                true,
                s(486),
                s(36),
                s(102),
                s(30),
            );

            let hwnd_current_only = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_CURRENT_ONLY,
                "現在表示中の会話のみ検索(&T)",
                false,
                s(16),
                s(72),
                s(572),
                s(22),
            );

            let lb_cls = to_wide("LISTBOX");
            let hwnd_list = unsafe {
                let h = CreateWindowExW(
                    WS_EX_CLIENTEDGE,
                    lb_cls.as_ptr(),
                    null(),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_TABSTOP
                        | WS_VSCROLL
                        | WS_BORDER
                        | (LBS_NOTIFY as u32)
                        | (LBS_NOINTEGRALHEIGHT as u32),
                    s(16),
                    s(102),
                    s(572),
                    s(210),
                    dlg,
                    IDC_DLG_SEARCH_LIST as _,
                    hinst,
                    null_mut(),
                );
                SendMessageW(h, WM_SETFONT, ui_font as usize, 1);
                h
            };

            let hwnd_status = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_STATUS,
                "キーワードを入力して「検索」を押してください。",
                s(16),
                s(320),
                s(572),
                s(20),
            );

            let _btn_jump = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_JUMP,
                "選択位置へ移動(&J)",
                false,
                s(340),
                s(348),
                s(140),
                s(30),
            );
            let _btn_close = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "閉じる(&C)",
                false,
                s(488),
                s(348),
                s(100),
                s(30),
            );

            let mut handler = SearchHandler {
                log_reader,
                active_thread,
                peer_names,
                hwnd_query,
                hwnd_current_only,
                hwnd_list,
                hwnd_status,
                hits: Vec::new(),
                last_query: Zeroizing::new(initial_q.clone()),
                jump_target: None,
            };
            if !initial_q.trim().is_empty() {
                handler.execute_search();
            }
            (handler, hwnd_query)
        },
    );

    SearchDialogResult {
        last_query: std::mem::take(&mut res.last_query),
        jump_target: res.jump_target.take(),
    }
}

pub(crate) fn show_about_dialog(parent: HWND, dpi: u32) {
    let text = format!(
        "{APP_NAME} v{APP_VERSION}\n\
         作成者: NRO / Antigravity\n\
         ライセンス: MIT License\n\n\
         [セキュリティ・ゼロパーシステンス方針]\n\
         - 会話履歴、パスワード、暗号鍵、表示名、ピア情報はディスクへ一切保存しません。\n\
         - UDP/TCP の全パケットをルーム派生鍵で ChaCha20-Poly1305 AEAD 認証・暗号化します。\n\
         - ログアウト・終了時および異常終了時はメモリをゼロクリアします。\n\n\
         [暗号仕様およびOS仕様上の留意事項]\n\
         - ルーム共通パスワードによる静的共有鍵方式のため、前方秘匿性（Forward Secrecy）はありません。\n\
         - パスワードが漏洩した場合、事前にキャプチャされた過去の暗号化通信も復号され得ます。\n\
         - 同一ルーム内の全メンバーが同じ共通鍵を保持するため、メンバー間の表示名詐称を暗号学的には識別できません。\n\
         - 信頼できるメンバー間で推測困難な 12文字以上のパスワードを使用し、定期的な変更を推奨します。\n\
         - 休止状態 (hiberfil.sys)、OS によるページング、管理者メモリダンプ、および手動コピーしたクリップボード履歴はアプリ単体で完全遮断できません。"
    );
    show_readonly_info_modal(
        parent,
        "バージョン情報 - ZeroHop",
        &text,
        false,
        false,
        590,
        420,
        dpi,
    );
}

pub(crate) fn pick_open_file_dialog(owner: HWND) -> Option<PathBuf> {
    let mut file_buf = vec![0u16; 4096];
    let filter: Vec<u16> = "すべてのファイル (*.*)\0*.*\0\0".encode_utf16().collect();
    let title = to_wide("送信するファイルを選択 (最大 50 MiB)");

    let mut ofn: OPENFILENAMEW = unsafe { zeroed() };
    ofn.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file_buf.as_mut_ptr();
    ofn.nMaxFile = file_buf.len() as u32;
    ofn.lpstrTitle = title.as_ptr();
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;

    let ok = unsafe { GetOpenFileNameW(&mut ofn) };
    if ok == 0 {
        return None;
    }
    let nul_pos = file_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(file_buf.len());
    let path_str = String::from_utf16_lossy(&file_buf[..nul_pos]);
    if path_str.is_empty() {
        None
    } else {
        Some(PathBuf::from(path_str))
    }
}

pub(crate) fn pick_save_file_dialog(owner: HWND, default_filename: &str) -> Option<PathBuf> {
    let mut file_buf = vec![0u16; 4096];
    let default_units: Vec<u16> = default_filename.encode_utf16().take(255).collect();
    file_buf[..default_units.len()].copy_from_slice(&default_units);

    let filter: Vec<u16> = "すべてのファイル (*.*)\0*.*\0\0".encode_utf16().collect();
    let title = to_wide("受信ファイルの保存先を指定");

    let mut ofn: OPENFILENAMEW = unsafe { zeroed() };
    ofn.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter.as_ptr();
    ofn.lpstrFile = file_buf.as_mut_ptr();
    ofn.nMaxFile = file_buf.len() as u32;
    ofn.lpstrTitle = title.as_ptr();
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    let ok = unsafe { GetSaveFileNameW(&mut ofn) };
    if ok == 0 {
        return None;
    }
    let nul_pos = file_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(file_buf.len());
    let path_str = String::from_utf16_lossy(&file_buf[..nul_pos]);
    if path_str.is_empty() {
        None
    } else {
        Some(PathBuf::from(path_str))
    }
}

pub(crate) fn confirm_file_offer_dialog(
    owner: HWND,
    peer_name: &str,
    filename: &str,
    file_size: u64,
    sha256_hex: &str,
) -> bool {
    let size_human = format_bytes_human(file_size as usize);
    let sha_short: String = sha256_hex.chars().take(16).collect();
    let msg = format!(
        "{peer_name} からファイル送信の要求があります。\n\n\
         ファイル名: {filename}\n\
         サイズ: {size_human} ({file_size} バイト)\n\
         SHA-256先頭: {sha_short}...\n\n\
         保存先を指定して受信しますか？"
    );
    let w_msg = to_wide(&msg);
    let w_title = to_wide("ファイル受信の確認 - ZeroHop");
    let ret = unsafe {
        MessageBoxW(
            owner,
            w_msg.as_ptr(),
            w_title.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        )
    };
    ret == IDYES
}
