//! ロック画面コントロール生成・レイアウト・解除送信。

use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::Graphics::Gdi::HFONT;
use windows_sys::Win32::System::SystemServices::{SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::EM_SETLIMITTEXT;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_DEFPUSHBUTTON, BS_PUSHBUTTON, ES_AUTOHSCROLL, ES_PASSWORD, MoveWindow, SW_HIDE, SW_SHOW,
    SendMessageW, SetWindowTextW, ShowWindow, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP,
};
use zeroize::Zeroizing;

use zerohop::app::state::{AppStateKind, UiCommand};

use super::a11y::{focus_control, safe_disable_window, set_cue_banner};
use super::state_helpers::{UiHandles, with_ui_and_state_mut};
use super::theme::scale_dpi;
use super::{
    IDC_LOCK_GUIDE, IDC_LOCK_LOGOUT_BTN, IDC_LOCK_PASS_EDIT, IDC_LOCK_PASS_LABEL, IDC_LOCK_STATUS,
    IDC_LOCK_TITLE, IDC_LOCK_UNLOCK_BTN, make_child_control, read_window_text_zeroizing, to_wide,
};

pub(crate) struct LockControlHandles {
    pub title: HWND,
    pub guide: HWND,
    pub pass_label: HWND,
    pub pass_edit: HWND,
    pub unlock_btn: HWND,
    pub logout_btn: HWND,
    pub status: HWND,
}

pub(crate) fn create_lock_controls(
    hwnd_parent: HWND,
    hinst: HANDLE,
    ui_font: HFONT,
    title_font: HFONT,
) -> LockControlHandles {
    let static_w = to_wide("STATIC");
    let edit_w = to_wide("EDIT");
    let button_w = to_wide("BUTTON");
    let static_style = WS_CHILD | SS_LEFT | SS_NOPREFIX;

    let title = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "画面ロック中 - ZeroHop",
        0,
        static_style,
        IDC_LOCK_TITLE,
        title_font,
    );
    let guide = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "会話内容と接続先一覧を非表示にしています。ルームパスワードを再入力してロックを解除してください。",
        0,
        static_style,
        IDC_LOCK_GUIDE,
        ui_font,
    );
    let pass_label = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "パスワード(&P):",
        0,
        static_style,
        IDC_LOCK_PASS_LABEL,
        ui_font,
    );
    let pass_edit = make_child_control(
        hwnd_parent,
        hinst,
        edit_w.as_ptr(),
        "",
        WS_EX_CLIENTEDGE,
        WS_CHILD | WS_TABSTOP | (ES_AUTOHSCROLL as u32) | (ES_PASSWORD as u32),
        IDC_LOCK_PASS_EDIT,
        ui_font,
    );
    unsafe {
        SendMessageW(pass_edit, EM_SETLIMITTEXT, 256, 0);
    }
    set_cue_banner(pass_edit, "ログイン時のパスワードを入力");

    let unlock_btn = make_child_control(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "ロック解除(&U)",
        0,
        WS_CHILD | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
        IDC_LOCK_UNLOCK_BTN,
        ui_font,
    );
    let logout_btn = make_child_control(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "ログアウトして全消去(&L)",
        0,
        WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_LOCK_LOGOUT_BTN,
        ui_font,
    );
    let status = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "",
        0,
        static_style,
        IDC_LOCK_STATUS,
        ui_font,
    );

    LockControlHandles {
        title,
        guide,
        pass_label,
        pass_edit,
        unlock_btn,
        logout_btn,
        status,
    }
}

pub(crate) fn layout_lock_controls(handles: &UiHandles, client_w: i32, client_h: i32, dpi: u32) {
    let s = |v| scale_dpi(v, dpi);
    let card_w = s(440).min((client_w - s(48)).max(s(280)));
    let x = ((client_w - card_w) / 2).max(s(20));
    let mut y = ((client_h - s(240)) / 2).max(s(28));

    unsafe {
        MoveWindow(handles.lock_title, x, y, card_w, s(32), 1);
        y += s(40);
        MoveWindow(handles.lock_guide, x, y, card_w, s(40), 1);
        y += s(48);
        MoveWindow(handles.lock_pass_label, x, y, card_w, s(20), 1);
        y += s(24);
        MoveWindow(handles.lock_pass_edit, x, y, card_w, s(28), 1);
        y += s(40);
        let btn_w = s(160);
        MoveWindow(handles.lock_unlock_btn, x, y, btn_w, s(32), 1);
        MoveWindow(
            handles.lock_logout_btn,
            x + btn_w + s(12),
            y,
            s(200),
            s(32),
            1,
        );
        y += s(42);
        MoveWindow(handles.lock_status, x, y, card_w, s(36), 1);
    }
}

pub(crate) fn show_lock_controls(handles: &UiHandles, visible: bool) {
    let cmd = if visible { SW_SHOW } else { SW_HIDE };
    unsafe {
        for hwnd in handles.lock_controls() {
            ShowWindow(hwnd, cmd);
        }
    }
}

pub(crate) fn submit_unlock() {
    enum UnlockPrep {
        FocusPass(HWND),
        Ready {
            pass_edit: HWND,
            unlock_btn: HWND,
            logout_btn: HWND,
            status: HWND,
            cmd_tx: tokio::sync::mpsc::Sender<UiCommand>,
            password: Zeroizing<String>,
        },
    }

    let prep = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::Locked {
            return None;
        }
        let password = read_window_text_zeroizing(handles.lock_pass_edit);
        if password.is_empty() {
            let msg = to_wide("パスワードを入力してください。");
            unsafe { SetWindowTextW(handles.lock_status, msg.as_ptr()) };
            return Some(UnlockPrep::FocusPass(handles.lock_pass_edit));
        }
        Some(UnlockPrep::Ready {
            pass_edit: handles.lock_pass_edit,
            unlock_btn: handles.lock_unlock_btn,
            logout_btn: handles.lock_logout_btn,
            status: handles.lock_status,
            cmd_tx: state.cmd_tx.clone(),
            password,
        })
    })
    .flatten();

    match prep {
        Some(UnlockPrep::FocusPass(pass_edit)) => {
            focus_control(pass_edit);
        }
        Some(UnlockPrep::Ready {
            pass_edit,
            unlock_btn,
            logout_btn,
            status,
            cmd_tx,
            password,
        }) => {
            let checking = to_wide("パスワードを検証しています...");
            unsafe {
                SetWindowTextW(status, checking.as_ptr());
                safe_disable_window(unlock_btn, logout_btn);
                EnableWindow(pass_edit, 0);
            }
            if cmd_tx
                .try_send(UiCommand::UnlockScreen { password })
                .is_err()
            {
                let err_w = to_wide("検証要求を送信できませんでした。");
                unsafe {
                    EnableWindow(pass_edit, 1);
                    EnableWindow(unlock_btn, 1);
                    SetWindowTextW(status, err_w.as_ptr());
                }
                focus_control(pass_edit);
            }
        }
        None => {}
    }
}
