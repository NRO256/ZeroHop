//! キーボード操作・フォーカス退避・スクリーンリーダーアクセシビリティ補助。

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::Controls::{
    EM_SETCUEBANNER, LVIS_FOCUSED, LVIS_SELECTED, LVITEMW, LVM_ENSUREVISIBLE, LVM_GETNEXTITEM,
    LVM_SETITEMSTATE, LVNI_SELECTED,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetFocus, IsWindowEnabled, SetFocus,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW;

use super::state_helpers::UiHandles;
use super::to_wide;

/// コントロールを無効化する前に、現在フォーカスが対象にある場合は有効な要素へ退避する。
pub(crate) fn safe_disable_window(target: HWND, fallback_focus: HWND) {
    if target.is_null() {
        return;
    }
    unsafe {
        if GetFocus() == target && !fallback_focus.is_null() && IsWindowEnabled(fallback_focus) != 0
        {
            SetFocus(fallback_focus);
        }
        EnableWindow(target, 0);
    }
}

pub(crate) fn focus_control(hwnd: HWND) {
    if hwnd.is_null() {
        return;
    }
    unsafe {
        if IsWindowEnabled(hwnd) != 0 {
            SetFocus(hwnd);
        }
    }
}

pub(crate) fn focus_listview_item(hwnd_lv: HWND, index: usize) {
    if hwnd_lv.is_null() {
        return;
    }
    let item = LVITEMW {
        mask: 0,
        iItem: index as i32,
        iSubItem: 0,
        state: LVIS_FOCUSED | LVIS_SELECTED,
        stateMask: LVIS_FOCUSED | LVIS_SELECTED,
        pszText: null_mut(),
        cchTextMax: 0,
        iImage: 0,
        lParam: 0,
        iIndent: 0,
        iGroupId: 0,
        cColumns: 0,
        puColumns: null_mut(),
        piColFmt: null_mut(),
        iGroup: 0,
    };
    unsafe {
        SendMessageW(
            hwnd_lv,
            LVM_SETITEMSTATE,
            index,
            (&raw const item) as LPARAM,
        );
        SendMessageW(hwnd_lv, LVM_ENSUREVISIBLE, index, 0);
        SetFocus(hwnd_lv);
    }
}

pub(crate) fn get_selected_listview_index(hwnd_lv: HWND) -> Option<usize> {
    if hwnd_lv.is_null() {
        return None;
    }
    let idx = unsafe {
        SendMessageW(
            hwnd_lv,
            LVM_GETNEXTITEM,
            usize::MAX,
            LVNI_SELECTED as LPARAM,
        )
    };
    if idx >= 0 { Some(idx as usize) } else { None }
}

pub(crate) fn set_cue_banner(hwnd_edit: HWND, text: &str) {
    if hwnd_edit.is_null() {
        return;
    }
    let wide = to_wide(text);
    unsafe {
        SendMessageW(hwnd_edit, EM_SETCUEBANNER, 1, wide.as_ptr() as LPARAM);
    }
}

pub(crate) fn cycle_main_pane_focus(handles: &UiHandles, reverse: bool) {
    let order = [
        handles.main_peer_list,
        handles.main_chat_list,
        handles.main_input_edit,
    ];
    let current = unsafe { GetFocus() };
    let idx = order.iter().position(|&h| h == current);
    let next = match (idx, reverse) {
        (Some(i), false) => order[(i + 1) % order.len()],
        (Some(0), true) => order[order.len() - 1],
        (Some(i), true) => order[i - 1],
        (None, false) => order[0],
        (None, true) => order[order.len() - 1],
    };
    focus_control(next);
}
