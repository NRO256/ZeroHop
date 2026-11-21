//! 安全なモーダルダイアログ群・クリップボードコピー・多重起動警告。

use std::cell::{Cell, RefCell};
use std::mem::{size_of, zeroed};
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
use windows_sys::Win32::UI::Controls::EM_SETLIMITTEXT;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus, VK_ESCAPE};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL,
    CBS_DROPDOWNLIST, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DC_HASDEFID, DM_GETDEFID,
    DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE,
    ES_NUMBER, ES_READONLY, GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, IDC_ARROW, IDCANCEL,
    IDOK, IsDialogMessageW, LoadCursorW, MB_ICONWARNING, MB_OK, MSG, MessageBoxW, PostQuitMessage,
    RegisterClassExW, SW_SHOW, SendMessageW, SetForegroundWindow, SetWindowLongPtrW,
    SetWindowTextW, ShowWindow, TranslateMessage, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_KEYDOWN,
    WM_SETFONT, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE,
    WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
    WS_VSCROLL,
};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use lan_messenger::domain::model::{MAX_MAX_MEMORY_MB, MIN_MAX_MEMORY_MB};
use lan_messenger::domain::validation::{ValidationError, validate_manual_peer_endpoint};
use lan_messenger::network::nic::{NicCandidate, discover_ipv4_nics};
use lan_messenger::storage::config::LocalConfig;
use lan_messenger::storage::paths::AppPaths;

use super::a11y::set_cue_banner;
use super::theme::{ThemeResources, apply_window_dwm_attributes, center_rect_on_parent, scale_dpi};
use super::{APP_NAME, APP_VERSION, normalize_crlf, read_window_text, to_wide};

const MODAL_CLASS_NAME: &str = "LanMessengerModalDialogClass";

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

const IDC_DLG_INFO_BODY: usize = 4401;
const IDC_DLG_INFO_COPY: usize = 4402;
const IDC_DLG_INFO_STATUS: usize = 4403;

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
    let title = to_wide("LanMessenger - 多重起動の確認");
    let msg = to_wide(
        "LanMessenger はすでに起動しています。\n\
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
            "終了の確認 - LanMessenger",
            "終了すると、現在の会話内容、暗号鍵、および一時キャッシュはすべて消去され復元できません。\r\nよろしいですか？",
            "全消去して終了(&Y)",
        )
    } else {
        (
            "ログアウトの確認 - LanMessenger",
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
        "メッセージ全文詳細 - LanMessenger",
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
        "手動ピア追加 - LanMessenger",
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

// 4. オプション設定ダイアログ（NIC・ポート・メモリ上限）
struct OptionsHandler {
    current_cfg: LocalConfig,
    nics: Vec<NicCandidate>,
    hwnd_nic: HWND,
    hwnd_udp: HWND,
    hwnd_tcp: HWND,
    hwnd_mem: HWND,
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
        "オプション設定 - LanMessenger",
        500,
        330,
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
                "会話ログ総メモリ上限 (4〜32 MiB)(&M):",
                s(16),
                s(134),
                s(452),
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

            let _lbl_note = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                persist_note,
                s(16),
                s(192),
                s(452),
                s(34),
            );
            let hwnd_err = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_ERR,
                "",
                s(16),
                s(228),
                s(452),
                s(20),
            );

            let _btn_ok = create_button(
                dlg,
                hinst,
                ui_font,
                IDOK as usize,
                "保存(&S)",
                true,
                s(258),
                s(252),
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
                s(368),
                s(252),
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
        "ルーム確認コード・通信情報 - LanMessenger",
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
  Ctrl + M             : 手動ピア追加（IP・ポート指定接続）\n\
  F5                   : ネットワーク再検出（NIC・ソケット再確認）\n\
  Ctrl + Shift + L     : ログアウト確認ダイアログ（全消去）\n\
  Ctrl + Shift + Del   : 現在表示中の会話表示をクリア\n\
  Alt + F4             : 終了（ログイン中は確認後に全消去して終了）\n\
\n\
[ログイン画面]\n\
  Enter                : 表示名・パスワード欄からログイン実行\n\
  Tab / Shift + Tab    : 入力欄・表示切替・ログイン・オプションを移動\n\
\n\
[会話一覧・入力欄]\n\
  上下矢印キー         : 会話メッセージ行または接続先を選択\n\
  Enter（会話一覧上）  : 選択メッセージの全文詳細ダイアログを開く（コピー・再送可）\n\
  Esc（詳細画面上）    : 詳細ダイアログを閉じて直前選択行へフォーカス復帰\n\
  Ctrl + Enter（入力欄）: メッセージを送信（Enter のみは改行）\n\
  Ctrl + A（入力欄）   : 入力テキストを全選択";
    show_readonly_info_modal(
        parent,
        "キーボードショートカット一覧 - LanMessenger",
        text,
        false,
        true,
        620,
        420,
        dpi,
    );
}

pub(crate) fn show_about_dialog(parent: HWND, dpi: u32) {
    let text = format!(
        "{APP_NAME} (LMSG) v{APP_VERSION}\n\
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
        "バージョン情報 - LanMessenger",
        &text,
        false,
        false,
        590,
        420,
        dpi,
    );
}
