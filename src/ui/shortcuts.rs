//! グローバルショートカットキーのメッセージループ前処理。

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetFocus, GetKeyState, VK_CONTROL, VK_DELETE, VK_F5, VK_F6, VK_MENU, VK_RETURN, VK_SHIFT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MSG, PostMessageW, WM_COMMAND, WM_KEYDOWN};

use zerohop::app::state::AppStateKind;

use super::a11y::cycle_main_pane_focus;
use super::lock_view::submit_unlock;
use super::login_view::submit_login;
use super::state_helpers::{with_ui, with_ui_and_state};
use super::{
    IDM_ADD_MANUAL_PEER, IDM_CLEAR_CURRENT, IDM_EXPORT_CHAT_LOG, IDM_INSERT_MENTION,
    IDM_LOCK_SCREEN, IDM_LOGOUT, IDM_REFRESH_NETWORK, IDM_SEARCH, IDM_SEND_FILE,
    WM_APP_OPEN_DETAIL,
};

pub(crate) fn handle_global_shortcut(hwnd: HWND, msg: &MSG) -> bool {
    if msg.message != WM_KEYDOWN {
        return false;
    }
    let ctrl = (unsafe { GetKeyState(i32::from(VK_CONTROL)) } as u16 & 0x8000) != 0;
    let shift = (unsafe { GetKeyState(i32::from(VK_SHIFT)) } as u16 & 0x8000) != 0;
    let alt = (unsafe { GetKeyState(i32::from(VK_MENU)) } as u16 & 0x8000) != 0;
    if alt {
        return false;
    }

    let snapshot = with_ui_and_state(|handles, state| {
        (
            state.app_state,
            handles.login_name_edit,
            handles.login_pass_edit,
            handles.main_chat_list,
            handles.lock_pass_edit,
        )
    });
    let Some((app_state, name_edit, pass_edit, chat_list, lock_pass_edit)) = snapshot else {
        return false;
    };

    if app_state == AppStateKind::LoggedOut
        && msg.wParam == usize::from(VK_RETURN)
        && !ctrl
        && !shift
    {
        let focus = unsafe { GetFocus() };
        if focus == name_edit
            || focus == pass_edit
            || msg.hwnd == name_edit
            || msg.hwnd == pass_edit
        {
            submit_login();
            return true;
        }
    }

    if app_state == AppStateKind::Locked {
        if msg.wParam == usize::from(VK_RETURN) && !ctrl && !shift {
            let focus = unsafe { GetFocus() };
            if focus == lock_pass_edit || msg.hwnd == lock_pass_edit {
                submit_unlock();
                return true;
            }
        }
        if ctrl && shift && msg.wParam == b'L' as usize {
            unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_LOGOUT, 0) };
            return true;
        }
        return false;
    }

    if app_state != AppStateKind::LoggedIn {
        return false;
    }

    if ctrl && !shift && msg.wParam == b'L' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_LOCK_SCREEN, 0) };
        return true;
    }
    if ctrl && !shift && msg.wParam == b'F' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_SEARCH, 0) };
        return true;
    }
    if ctrl && !shift && msg.wParam == b'S' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_EXPORT_CHAT_LOG, 0) };
        return true;
    }
    if ctrl && shift && msg.wParam == b'F' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_SEND_FILE, 0) };
        return true;
    }

    if ctrl && shift && msg.wParam == b'L' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_LOGOUT, 0) };
        return true;
    }
    if ctrl && shift && msg.wParam == usize::from(VK_DELETE) {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_CLEAR_CURRENT, 0) };
        return true;
    }
    if ctrl && !shift && msg.wParam == b'M' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_ADD_MANUAL_PEER, 0) };
        return true;
    }
    if ctrl && shift && msg.wParam == b'M' as usize {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_INSERT_MENTION, 0) };
        return true;
    }
    if !ctrl && !shift && msg.wParam == usize::from(VK_F5) {
        unsafe { PostMessageW(hwnd, WM_COMMAND, IDM_REFRESH_NETWORK, 0) };
        return true;
    }
    if !ctrl && msg.wParam == usize::from(VK_F6) {
        with_ui(|handles| cycle_main_pane_focus(handles, shift));
        return true;
    }
    if !ctrl && !shift && msg.wParam == usize::from(VK_RETURN) {
        let focus = unsafe { GetFocus() };
        if focus == chat_list || msg.hwnd == chat_list {
            unsafe { PostMessageW(hwnd, WM_APP_OPEN_DETAIL, 0, 0) };
            return true;
        }
    }

    false
}
