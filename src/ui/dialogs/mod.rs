//! 安全なモーダルダイアログ群・クリップボードコピー・多重起動警告。

mod detail;
mod manual_peer;
mod options;
mod search;

use std::cell::{Cell, RefCell};
use std::mem::{size_of, zeroed};
use std::path::PathBuf;
use std::ptr::null_mut;

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
    CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DC_HASDEFID, DM_GETDEFID, DefWindowProcW,
    DestroyWindow, DispatchMessageW, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, GWLP_USERDATA,
    GetMessageW, GetWindowLongPtrW, IDC_ARROW, IDCANCEL, IDOK, IDYES, IsDialogMessageW,
    LoadCursorW, MB_DEFBUTTON2, MB_ICONQUESTION, MB_ICONWARNING, MB_OK, MB_YESNO, MSG, MessageBoxW,
    PostQuitMessage, RegisterClassExW, SW_SHOW, SendMessageW, SetForegroundWindow,
    SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, WM_CLOSE, WM_COMMAND,
    WM_DESTROY, WM_KEYDOWN, WM_SETFONT, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_EX_CLIENTEDGE, WS_EX_CONTROLPARENT, WS_EX_DLGMODALFRAME, WS_POPUP, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE, WS_VSCROLL,
};
use zeroize::Zeroize;

use super::theme::{ThemeResources, apply_window_dwm_attributes, center_rect_on_parent, scale_dpi};
use super::{APP_NAME, APP_VERSION, format_bytes_human, normalize_crlf, to_wide};

pub(crate) use detail::{DetailDialogAction, DetailDialogInput, show_message_detail_dialog};
pub(crate) use manual_peer::show_add_manual_peer_dialog;
pub(crate) use options::show_options_dialog;
pub(crate) use search::show_search_dialog;

const MODAL_CLASS_NAME: &str = "ZeroHopModalDialogClass";

const IDC_DLG_INFO_BODY: usize = 4401;
const IDC_DLG_INFO_COPY: usize = 4402;
const IDC_DLG_INFO_STATUS: usize = 4403;

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
    let hinst = unsafe { GetModuleHandleW(std::ptr::null()) };
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

// 2. 情報表示用モーダル共通（通信情報・ショートカット一覧・バージョン情報）
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

// 3. ファイル送受信ダイアログ (Phase 3)
fn extract_ofn_path(file_buf: &[u16]) -> Option<PathBuf> {
    let nul_pos = file_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(file_buf.len());
    let path_str = String::from_utf16_lossy(&file_buf[..nul_pos]);
    (!path_str.is_empty()).then(|| PathBuf::from(path_str))
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
    (ok != 0).then(|| extract_ofn_path(&file_buf)).flatten()
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
    (ok != 0).then(|| extract_ofn_path(&file_buf)).flatten()
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
