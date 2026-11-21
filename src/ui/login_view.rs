//! 起動画面・ログアウト後ログインフォーム。

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::Graphics::Gdi::HFONT;
use windows_sys::Win32::System::SystemServices::{SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::{
    BST_CHECKED, BST_UNCHECKED, EM_SETLIMITTEXT, EM_SETPASSWORDCHAR,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CreateWindowExW,
    ES_AUTOHSCROLL, ES_PASSWORD, MoveWindow, SW_HIDE, SW_SHOW, SendMessageW, SetWindowTextW,
    ShowWindow, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VISIBLE,
};

use lan_messenger::app::state::{AppStateKind, UiCommand};
use lan_messenger::domain::model::MAX_DISPLAY_NAME_CHARS;
use lan_messenger::domain::validation::{
    evaluate_password_strength, validate_and_normalize_display_name, validate_password,
};

use super::a11y::{focus_control, safe_disable_window, set_cue_banner};
use super::state_helpers::{UiHandles, with_ui, with_ui_and_state_mut};
use super::theme::scale_dpi;
use super::{
    IDC_LOGIN_CANCEL, IDC_LOGIN_NAME_EDIT, IDC_LOGIN_NAME_LABEL, IDC_LOGIN_OPTIONS,
    IDC_LOGIN_PASS_EDIT, IDC_LOGIN_PASS_GUIDE, IDC_LOGIN_PASS_LABEL, IDC_LOGIN_SHOW_PASS,
    IDC_LOGIN_STATUS, IDC_LOGIN_SUBMIT, IDC_LOGIN_SUBTITLE, IDC_LOGIN_TITLE, read_window_text,
    read_window_text_zeroizing, to_wide,
};

const PASSWORD_MASK_CHAR: usize = 0x25CF; // ●

#[allow(clippy::too_many_arguments)]
fn make_ctrl(
    parent: HWND,
    hinst: HANDLE,
    class: &str,
    text: &str,
    ex_style: u32,
    style: u32,
    id: usize,
    font: HFONT,
) -> HWND {
    let cls_w = to_wide(class);
    let txt_w = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            ex_style,
            cls_w.as_ptr(),
            txt_w.as_ptr(),
            style,
            0,
            0,
            100,
            24,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(
            hwnd,
            windows_sys::Win32::UI::WindowsAndMessaging::WM_SETFONT,
            font as usize,
            1,
        );
        hwnd
    }
}

pub(crate) fn create_login_controls(
    hwnd_parent: HWND,
    hinst: HANDLE,
    ui_font: HFONT,
    bold_font: HFONT,
) -> LoginControlHandles {
    let static_style = WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX;
    let edit_style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | (ES_AUTOHSCROLL as u32);

    let title = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "LanMessenger (LMSG)",
        0,
        static_style,
        IDC_LOGIN_TITLE,
        bold_font,
    );
    let subtitle = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "履歴をディスクに残さない暗号化 LAN メッセンジャー。表示名とルームパスワードを入力してログインしてください。",
        0,
        static_style,
        IDC_LOGIN_SUBTITLE,
        ui_font,
    );
    let name_label = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "表示名 (1〜32文字)(&N):",
        0,
        static_style,
        IDC_LOGIN_NAME_LABEL,
        ui_font,
    );
    let name_edit = make_ctrl(
        hwnd_parent,
        hinst,
        "EDIT",
        "",
        WS_EX_CLIENTEDGE,
        edit_style,
        IDC_LOGIN_NAME_EDIT,
        ui_font,
    );
    unsafe {
        SendMessageW(name_edit, EM_SETLIMITTEXT, MAX_DISPLAY_NAME_CHARS, 0);
    }
    set_cue_banner(name_edit, "例: 田中太郎");

    let pass_label = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "パスワード / ルーム共通鍵 (8文字以上)(&P):",
        0,
        static_style,
        IDC_LOGIN_PASS_LABEL,
        ui_font,
    );
    let pass_edit = make_ctrl(
        hwnd_parent,
        hinst,
        "EDIT",
        "",
        WS_EX_CLIENTEDGE,
        edit_style | (ES_PASSWORD as u32),
        IDC_LOGIN_PASS_EDIT,
        ui_font,
    );
    unsafe {
        SendMessageW(pass_edit, EM_SETPASSWORDCHAR, PASSWORD_MASK_CHAR, 0);
    }
    set_cue_banner(pass_edit, "12文字以上・英数記号混在を推奨");

    let pass_guide = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "入力文字数: 0文字（8文字以上必須 / 12文字以上・英数記号混在推奨）",
        0,
        static_style,
        IDC_LOGIN_PASS_GUIDE,
        ui_font,
    );
    let show_pass = make_ctrl(
        hwnd_parent,
        hinst,
        "BUTTON",
        "パスワードを表示(&S)",
        0,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_AUTOCHECKBOX as u32),
        IDC_LOGIN_SHOW_PASS,
        ui_font,
    );
    let submit = make_ctrl(
        hwnd_parent,
        hinst,
        "BUTTON",
        "ログイン(&L)",
        0,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_DEFPUSHBUTTON as u32),
        IDC_LOGIN_SUBMIT,
        ui_font,
    );
    let cancel = make_ctrl(
        hwnd_parent,
        hinst,
        "BUTTON",
        "キャンセル(&C)",
        0,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_LOGIN_CANCEL,
        ui_font,
    );
    unsafe {
        EnableWindow(cancel, 0);
    }
    let options = make_ctrl(
        hwnd_parent,
        hinst,
        "BUTTON",
        "オプション設定(&O)...",
        0,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_LOGIN_OPTIONS,
        ui_font,
    );
    let status = make_ctrl(
        hwnd_parent,
        hinst,
        "STATIC",
        "",
        0,
        static_style,
        IDC_LOGIN_STATUS,
        ui_font,
    );

    LoginControlHandles {
        title,
        subtitle,
        name_label,
        name_edit,
        pass_label,
        pass_edit,
        pass_guide,
        show_pass,
        submit,
        cancel,
        options,
        status,
    }
}

pub(crate) struct LoginControlHandles {
    pub title: HWND,
    pub subtitle: HWND,
    pub name_label: HWND,
    pub name_edit: HWND,
    pub pass_label: HWND,
    pub pass_edit: HWND,
    pub pass_guide: HWND,
    pub show_pass: HWND,
    pub submit: HWND,
    pub cancel: HWND,
    pub options: HWND,
    pub status: HWND,
}

pub(crate) fn layout_login_controls(handles: &UiHandles, client_w: i32, client_h: i32, dpi: u32) {
    let s = |v| scale_dpi(v, dpi);
    let card_w = s(500).min((client_w - s(48)).max(s(320)));
    let x = ((client_w - card_w) / 2).max(s(20));
    let total_h = s(370);
    let mut y = ((client_h - total_h) / 2).max(s(24));

    unsafe {
        MoveWindow(handles.login_title, x, y, card_w, s(28), 1);
        y += s(32);
        MoveWindow(handles.login_subtitle, x, y, card_w, s(42), 1);
        y += s(52);

        MoveWindow(handles.login_name_label, x, y, card_w, s(22), 1);
        y += s(24);
        MoveWindow(handles.login_name_edit, x, y, card_w, s(28), 1);
        y += s(40);

        MoveWindow(handles.login_pass_label, x, y, card_w, s(22), 1);
        y += s(24);
        MoveWindow(handles.login_pass_edit, x, y, card_w, s(28), 1);
        y += s(34);
        MoveWindow(handles.login_pass_guide, x, y, card_w, s(22), 1);
        y += s(26);
        MoveWindow(handles.login_show_pass, x, y, s(220), s(24), 1);
        y += s(36);

        let btn_w = s(136);
        let opt_w = s(170);
        MoveWindow(handles.login_submit, x, y, btn_w, s(32), 1);
        MoveWindow(handles.login_cancel, x + btn_w + s(12), y, s(120), s(32), 1);
        MoveWindow(
            handles.login_options,
            x + card_w - opt_w,
            y,
            opt_w,
            s(32),
            1,
        );
        y += s(44);

        MoveWindow(handles.login_status, x, y, card_w, s(48), 1);
    }
}

pub(crate) fn show_login_controls(handles: &UiHandles, visible: bool) {
    let cmd = if visible { SW_SHOW } else { SW_HIDE };
    unsafe {
        for hwnd in handles.login_controls() {
            ShowWindow(hwnd, cmd);
        }
    }
}

pub(crate) fn set_login_status_message(handles: &UiHandles, msg: &str) {
    let w = to_wide(msg);
    unsafe {
        SetWindowTextW(handles.login_status, w.as_ptr());
    }
}

pub(crate) fn update_password_guide(handles: &UiHandles) {
    let pw = read_window_text_zeroizing(handles.login_pass_edit);
    let len = pw.chars().count();
    let msg = if len == 0 {
        "入力文字数: 0文字（8文字以上必須 / 12文字以上・英数記号混在推奨）".to_string()
    } else if len < 8 {
        format!("入力文字数: {len}文字（あと{}文字以上必要です）", 8 - len)
    } else {
        let strength = evaluate_password_strength(&pw);
        format!("入力文字数: {len}文字 — 強度: {}", strength.label_ja())
    };
    let w = to_wide(&msg);
    unsafe {
        SetWindowTextW(handles.login_pass_guide, w.as_ptr());
    }
}

pub(crate) fn toggle_password_visibility(handles: &UiHandles) {
    unsafe {
        let checked =
            SendMessageW(handles.login_show_pass, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
        let ch = if checked { 0 } else { PASSWORD_MASK_CHAR };
        SendMessageW(handles.login_pass_edit, EM_SETPASSWORDCHAR, ch, 0);
        let _ =
            windows_sys::Win32::Graphics::Gdi::InvalidateRect(handles.login_pass_edit, null(), 1);
    }
}

pub(crate) fn reset_login_form(handles: &UiHandles, focus_name: bool) {
    let empty = to_wide("");
    unsafe {
        SetWindowTextW(handles.login_name_edit, empty.as_ptr());
        SetWindowTextW(handles.login_pass_edit, empty.as_ptr());
        SendMessageW(
            handles.login_show_pass,
            BM_SETCHECK,
            BST_UNCHECKED as usize,
            0,
        );
        SendMessageW(
            handles.login_pass_edit,
            EM_SETPASSWORDCHAR,
            PASSWORD_MASK_CHAR,
            0,
        );
    }
    update_password_guide(handles);
    set_login_status_message(handles, "");
    if focus_name {
        focus_control(handles.login_name_edit);
    }
}

pub(crate) fn set_authenticating_ui(handles: &UiHandles, authenticating: bool) {
    if authenticating {
        unsafe {
            EnableWindow(handles.login_cancel, 1);
        }
        focus_control(handles.login_cancel);
        for target in [
            handles.login_name_edit,
            handles.login_pass_edit,
            handles.login_show_pass,
            handles.login_submit,
            handles.login_options,
        ] {
            safe_disable_window(target, handles.login_cancel);
        }
        set_login_status_message(
            handles,
            "鍵を導出しています（Argon2id）... しばらくお待ちください。",
        );
    } else {
        for target in [
            handles.login_name_edit,
            handles.login_pass_edit,
            handles.login_show_pass,
            handles.login_submit,
            handles.login_options,
        ] {
            unsafe {
                EnableWindow(target, 1);
            }
        }
        safe_disable_window(handles.login_cancel, handles.login_pass_edit);
    }
}

pub(crate) fn submit_login() {
    let inputs = with_ui(|handles| {
        let raw_name = read_window_text(handles.login_name_edit);
        let password = read_window_text_zeroizing(handles.login_pass_edit);
        (raw_name, password)
    });
    let Some((raw_name, password)) = inputs else {
        return;
    };

    let clean_name = match validate_and_normalize_display_name(&raw_name) {
        Ok(name) => name,
        Err(err) => {
            with_ui(|handles| {
                set_login_status_message(handles, &err.to_string());
                focus_control(handles.login_name_edit);
            });
            return;
        }
    };

    if validate_password(&password).is_err() {
        with_ui(|handles| {
            set_login_status_message(
                handles,
                "パスワードは8文字以上を入力してください（12文字以上・英数記号混在を推奨）",
            );
            focus_control(handles.login_pass_edit);
        });
        return;
    }

    let fail_focus = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedOut {
            return None;
        }
        if state
            .cmd_tx
            .try_send(UiCommand::LoginRequest {
                display_name: clean_name,
                password,
            })
            .is_err()
        {
            set_login_status_message(
                handles,
                "ログイン要求の送信に失敗しました。再度お試しください。",
            );
            return Some(handles.login_submit);
        }
        state.app_state = AppStateKind::Authenticating;
        set_authenticating_ui(handles, true);
        None
    })
    .flatten();
    if let Some(target) = fail_focus {
        focus_control(target);
    }
}
