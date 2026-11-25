//! Win32 Presentation 層エントリ・定数・純粋変換ヘルパー・メインウィンドウ調停。

pub mod a11y;
pub mod dialogs;
pub mod events;
pub mod formats;
pub mod lock_view;
pub mod login_view;
pub mod main_view;
pub mod menu_bar;
pub mod shortcuts;
pub mod sound;
pub mod state_helpers;
pub mod theme;
pub mod transfer_ui;

use std::collections::{HashMap, VecDeque};
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc::error::TrySendError;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_BTNFACE, GetSysColorBrush, HFONT, InvalidateRect, SetBkColor, SetTextColor,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetFocus, GetLastInputInfo, LASTINPUTINFO};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW,
    DestroyMenu, DestroyWindow, DispatchMessageW, EN_CHANGE, GetClientRect, GetMessageW, IDC_ARROW,
    IsDialogMessageW, KillTimer, LBN_SELCHANGE, LoadCursorW, MINMAXINFO, MSG, PostMessageW,
    PostQuitMessage, RegisterClassExW, SW_SHOW, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW,
    SetMenu, SetTimer, SetWindowPos, ShowWindow, TranslateMessage, WA_INACTIVE, WM_ACTIVATE,
    WM_APP, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED,
    WM_GETMINMAXINFO, WM_NOTIFY, WM_SETFONT, WM_SETTINGCHANGE, WM_SIZE, WM_THEMECHANGED, WM_TIMER,
    WNDCLASSEXW, WS_EX_CONTROLPARENT, WS_OVERLAPPEDWINDOW,
};
use zeroize::{Zeroize, Zeroizing};

use zerohop::app::coordinator::{CoordinatorOptions, spawn_coordinator};
use zerohop::app::state::{AppStateKind, UiCommand};
use zerohop::domain::model::{ThreadKey, UserStatus};
use zerohop::storage::config::LocalConfig;
use zerohop::storage::paths::AppPaths;

use a11y::focus_control;
use dialogs::{
    confirm_logout_or_exit, show_about_dialog, show_add_manual_peer_dialog,
    show_connection_info_dialog, show_options_dialog, show_search_dialog, show_shortcuts_dialog,
};
use events::{drain_app_events, remove_tray_icon};
pub(crate) use formats::{
    build_connection_info_text, format_bytes_human, format_remaining_bytes_label,
    format_unix_datetime, format_unix_time_hms, is_message_retryable, normalize_crlf,
    normalized_utf8_byte_len, resolve_migrated_thread, summarize_message_body,
};
use lock_view::{create_lock_controls, layout_lock_controls, show_lock_controls, submit_unlock};
use login_view::{
    create_login_controls, layout_login_controls, reset_login_form, set_authenticating_ui,
    set_login_status_message, show_login_controls, submit_login, toggle_password_visibility,
    update_password_guide,
};
use main_view::{
    apply_clear_main_controls, clear_unread_for_thread, create_main_controls,
    extract_clear_main_args, handle_lv_getdispinfo, handle_peer_list_selchange, jump_to_search_hit,
    layout_main_controls, open_selected_message_detail, refresh_peer_list, remove_main_subclasses,
    retry_selected_message, send_current_input, set_input_send_on_enter, set_notice_text,
    show_main_controls, update_input_byte_guide, update_status_bar,
};
use menu_bar::{
    create_main_menu_bar, sync_menu_enabled_state, sync_option_menu_checks, sync_status_menu_check,
};
use shortcuts::handle_global_shortcut;
use sound::SoundController;
use state_helpers::{
    UiHandles, UiState, clear_thread_locals, guard_wnd_proc, init_thread_locals, with_state,
    with_state_mut, with_ui, with_ui_and_state, with_ui_and_state_mut,
};
use theme::{
    CLR_NOTICE_TEXT, ThemeResources, apply_listview_explorer_theme, apply_window_dwm_attributes,
    center_rect_on_cursor_monitor, is_high_contrast, scale_dpi,
};
use transfer_ui::{
    cancel_active_file_transfer, handle_file_button_clicked, process_pending_file_offers,
    start_send_file_flow,
};

pub(crate) const APP_NAME: &str = "ZeroHop";
pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const WM_APP_EVENT: u32 = WM_APP + 1;
pub(crate) const WM_APP_OPEN_DETAIL: u32 = WM_APP + 2;
pub(crate) const WM_APP_TRAY_CALLBACK: u32 = WM_APP + 3;

pub(crate) const TIMER_AUTO_AWAY: usize = 1;

// メニューコマンド ID (Phase 1〜2)
pub(crate) const IDM_STATUS_ONLINE: usize = 1001;
pub(crate) const IDM_STATUS_AWAY: usize = 1002;
pub(crate) const IDM_STATUS_BUSY: usize = 1003;
pub(crate) const IDM_LOGOUT: usize = 1004;
pub(crate) const IDM_EXIT: usize = 1005;
pub(crate) const IDM_SHOW_DETAIL: usize = 1006;
pub(crate) const IDM_RETRY_SELECTED: usize = 1007;
pub(crate) const IDM_CLEAR_CURRENT: usize = 1008;
pub(crate) const IDM_CLEAR_ALL: usize = 1009;
pub(crate) const IDM_ADD_MANUAL_PEER: usize = 1010;
pub(crate) const IDM_REFRESH_NETWORK: usize = 1011;
pub(crate) const IDM_CONN_INFO: usize = 1012;
pub(crate) const IDM_OPTIONS: usize = 1013;
pub(crate) const IDM_SHORTCUTS: usize = 1014;
pub(crate) const IDM_ABOUT: usize = 1015;
pub(crate) const IDM_LOCK_SCREEN: usize = 1016;
pub(crate) const IDM_SEARCH: usize = 1017;
pub(crate) const IDM_TOGGLE_SOUND: usize = 1018;
pub(crate) const IDM_TOGGLE_SEND_ON_ENTER: usize = 1019;
pub(crate) const IDM_SEND_FILE: usize = 1020;
pub(crate) const IDM_CANCEL_FILE_TRANSFER: usize = 1021;

// ログイン画面コントロール ID
pub(crate) const IDC_LOGIN_TITLE: usize = 2001;
pub(crate) const IDC_LOGIN_SUBTITLE: usize = 2002;
pub(crate) const IDC_LOGIN_NAME_LABEL: usize = 2003;
pub(crate) const IDC_LOGIN_NAME_EDIT: usize = 2004;
pub(crate) const IDC_LOGIN_PASS_LABEL: usize = 2005;
pub(crate) const IDC_LOGIN_PASS_EDIT: usize = 2006;
pub(crate) const IDC_LOGIN_PASS_GUIDE: usize = 2007;
pub(crate) const IDC_LOGIN_SHOW_PASS: usize = 2008;
pub(crate) const IDC_LOGIN_SUBMIT: usize = 2009;
pub(crate) const IDC_LOGIN_CANCEL: usize = 2010;
pub(crate) const IDC_LOGIN_OPTIONS: usize = 2011;
pub(crate) const IDC_LOGIN_STATUS: usize = 2012;

// メイン画面コントロール ID
pub(crate) const IDC_MAIN_PEER_LABEL: usize = 3001;
pub(crate) const IDC_MAIN_PEER_LIST: usize = 3002;
pub(crate) const IDC_MAIN_THREAD_HEADER: usize = 3003;
pub(crate) const IDC_MAIN_NOTICE: usize = 3004;
pub(crate) const IDC_MAIN_CHAT_LIST: usize = 3005;
pub(crate) const IDC_MAIN_BYTE_GUIDE: usize = 3006;
pub(crate) const IDC_MAIN_INPUT_EDIT: usize = 3007;
pub(crate) const IDC_MAIN_SEND_BTN: usize = 3008;
pub(crate) const IDC_MAIN_STATUSBAR: usize = 3009;
pub(crate) const IDC_MAIN_FILE_BTN: usize = 3010;

// ロック画面コントロール ID (Phase 2)
pub(crate) const IDC_LOCK_TITLE: usize = 4001;
pub(crate) const IDC_LOCK_GUIDE: usize = 4002;
pub(crate) const IDC_LOCK_PASS_LABEL: usize = 4003;
pub(crate) const IDC_LOCK_PASS_EDIT: usize = 4004;
pub(crate) const IDC_LOCK_UNLOCK_BTN: usize = 4005;
pub(crate) const IDC_LOCK_LOGOUT_BTN: usize = 4006;
pub(crate) const IDC_LOCK_STATUS: usize = 4007;

pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_child_control(
    parent: HWND,
    hinst: HANDLE,
    class_w: *const u16,
    text: &str,
    ex_style: u32,
    style: u32,
    id: usize,
    font: HFONT,
) -> HWND {
    let txt_w = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            ex_style,
            class_w,
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
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        hwnd
    }
}

pub(crate) fn write_utf16_buf(dst: *mut u16, cap: i32, text: &str) {
    if dst.is_null() || cap <= 0 {
        return;
    }
    let max_units = (cap as usize).saturating_sub(1);
    let mut units: Vec<u16> = text.encode_utf16().take(max_units).collect();
    if units.len() == max_units
        && let Some(&last) = units.last()
        && (0xD800..=0xDBFF).contains(&last)
    {
        units.pop();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), dst, units.len());
        *dst.add(units.len()) = 0;
    }
    units.zeroize();
}

pub(crate) fn read_window_text(hwnd: HWND) -> String {
    if hwnd.is_null() {
        return String::new();
    }
    unsafe {
        let len = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (len as usize) + 1];
        let max_len = buf.len().min(i32::MAX as usize) as i32;
        let copied = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextW(
            hwnd,
            buf.as_mut_ptr(),
            max_len,
        );
        if copied <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..copied as usize])
    }
}

pub(crate) fn read_window_text_zeroizing(hwnd: HWND) -> Zeroizing<String> {
    if hwnd.is_null() {
        return Zeroizing::new(String::new());
    }
    unsafe {
        let len = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return Zeroizing::new(String::new());
        }
        let mut buf = vec![0u16; (len as usize) + 1];
        let max_len = buf.len().min(i32::MAX as usize) as i32;
        let copied = windows_sys::Win32::UI::WindowsAndMessaging::GetWindowTextW(
            hwnd,
            buf.as_mut_ptr(),
            max_len,
        );
        let mut text = String::new();
        if copied > 0 {
            let used = (copied as usize).min(buf.len());
            text.reserve(used.saturating_mul(3));
            for res in char::decode_utf16(buf[..used].iter().copied()) {
                text.push(res.unwrap_or('\u{FFFD}'));
            }
        }
        buf.zeroize();
        Zeroizing::new(text)
    }
}

struct PendingWindowInit {
    paths: AppPaths,
    config: LocalConfig,
    multi_instance: bool,
    window_alive: Arc<AtomicBool>,
    runtime_handle: tokio::runtime::Handle,
    join_slot: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

fn run_guarded_modal<Snap, Res, Post>(
    hwnd: HWND,
    prepare: impl FnOnce(&mut UiState) -> Option<Snap>,
    show: impl FnOnce(Snap) -> Res,
    finish: impl FnOnce(&mut UiHandles, &mut UiState, Res) -> Post,
    after: impl FnOnce(Post),
) {
    let Some(snap) = with_state_mut(|s| {
        if s.modal_open {
            return None;
        }
        let snap = prepare(s)?;
        s.modal_open = true;
        Some(snap)
    })
    .flatten() else {
        return;
    };

    let res = show(snap);
    let post = with_ui_and_state_mut(|handles, state| {
        state.modal_open = false;
        finish(handles, state, res)
    });
    if let Some(p) = post {
        after(p);
    }
    process_pending_file_offers(hwnd);
}

fn handle_options_modal(hwnd: HWND) {
    run_guarded_modal(
        hwnd,
        |s| Some((s.config.clone(), s.paths.clone(), s.dpi)),
        |(cfg, paths, dpi)| show_options_dialog(hwnd, &cfg, &paths, dpi),
        |handles, state, updated| {
            let new_cfg = updated?;
            let port_or_nic_changed = new_cfg.udp_port != state.config.udp_port
                || new_cfg.tcp_port != state.config.tcp_port
                || new_cfg.preferred_nic_ip != state.config.preferred_nic_ip;
            state.config = new_cfg.clone();
            set_input_send_on_enter(handles.main_input_edit, state.config.send_on_enter);
            update_input_byte_guide(handles, state.config.send_on_enter);
            sync_option_menu_checks(handles.hmenu_main, &state.config);
            let _ = state.cmd_tx.try_send(UiCommand::UpdateConfig(new_cfg));
            if state.app_state == AppStateKind::LoggedIn {
                if port_or_nic_changed {
                    set_notice_text(
                        handles,
                        state,
                        "設定を保存しました。ポート変更は次回ログイン時、NIC設定は「ネットワーク再検出」で反映されます。",
                    );
                } else {
                    set_notice_text(handles, state, "オプション設定を反映しました。");
                }
                Some(handles.main_input_edit)
            } else {
                set_login_status_message(handles, "オプション設定を更新しました。");
                Some(handles.login_name_edit)
            }
        },
        |target_opt| {
            if let Some(target) = target_opt {
                focus_control(target);
            }
        },
    );
}

fn handle_manual_peer_modal(hwnd: HWND) {
    run_guarded_modal(
        hwnd,
        |s| (s.app_state == AppStateKind::LoggedIn).then_some((s.config.tcp_port, s.dpi)),
        |(def_port, dpi)| show_add_manual_peer_dialog(hwnd, def_port, dpi),
        |handles, state, res| {
            if let Some((host, tcp_port)) = res
                && state.app_state == AppStateKind::LoggedIn
            {
                if state
                    .cmd_tx
                    .try_send(UiCommand::AddManualPeer {
                        host: host.clone(),
                        tcp_port,
                    })
                    .is_err()
                {
                    set_notice_text(
                        handles,
                        state,
                        "手動ピア追加要求の送信に失敗しました。再度お試しください。",
                    );
                } else {
                    set_notice_text(
                        handles,
                        state,
                        &format!("{host}:{tcp_port} へ手動ピア接続を試行しています..."),
                    );
                }
            }
            (state.app_state == AppStateKind::LoggedIn).then_some(handles.main_peer_list)
        },
        |target_opt| {
            if let Some(target) = target_opt {
                focus_control(target);
            }
        },
    );
}

fn handle_search_modal(hwnd: HWND) {
    run_guarded_modal(
        hwnd,
        |s| {
            (s.app_state == AppStateKind::LoggedIn).then(|| {
                (
                    s.log_reader.clone(),
                    s.active_thread.clone(),
                    s.peers.clone(),
                    s.last_search_query.clone(),
                    s.dpi,
                )
            })
        },
        |(log_reader, active_thread, peers, last_query, dpi)| {
            show_search_dialog(hwnd, log_reader, active_thread, &peers, &last_query, dpi)
        },
        |_, state, mut res| {
            if state.app_state == AppStateKind::LoggedIn {
                state.last_search_query = std::mem::take(&mut res.last_query);
            }
            res.jump_target.take()
        },
        |jump_opt| {
            if let Some((thread, index)) = jump_opt {
                jump_to_search_hit(thread, index);
            }
        },
    );
}

fn handle_logout_request(hwnd: HWND) {
    let snapshot = with_state_mut(|s| {
        if s.modal_open || !matches!(s.app_state, AppStateKind::LoggedIn | AppStateKind::Locked) {
            return None;
        }
        s.modal_open = true;
        Some(s.dpi)
    })
    .flatten();
    let Some(dpi) = snapshot else {
        return;
    };

    let confirmed = confirm_logout_or_exit(hwnd, false, dpi);
    let post = with_ui_and_state_mut(|handles, state| {
        state.modal_open = false;
        if !confirmed
            || !matches!(
                state.app_state,
                AppStateKind::LoggedIn | AppStateKind::Locked
            )
        {
            return None;
        }
        match state.cmd_tx.try_send(UiCommand::Logout) {
            Ok(()) => {
                state.app_state = AppStateKind::LoggingOut;
                Some((extract_clear_main_args(handles, state), None))
            }
            Err(TrySendError::Full(_)) => {
                set_notice_text(
                    handles,
                    state,
                    "ログアウト指示の送信に失敗しました（送信キュー混雑）。再度お試しください。",
                );
                None
            }
            Err(TrySendError::Closed(_)) => {
                let clear_args = extract_clear_main_args(handles, state);
                state.app_state = AppStateKind::LoggedOut;
                remove_tray_icon(hwnd, &mut state.tray_icon_added);
                state.clear_session_fields();
                unsafe {
                    SetMenu(hwnd, null_mut());
                    windows_sys::Win32::UI::WindowsAndMessaging::DrawMenuBar(hwnd);
                }
                menu_bar::sync_menu_enabled_state(handles.hmenu_main, AppStateKind::LoggedOut);
                show_lock_controls(handles, false);
                show_main_controls(handles, false);
                show_login_controls(handles, true);
                set_authenticating_ui(handles, false);
                reset_login_form(handles, false);
                set_login_status_message(handles, "バックエンド終了に伴い強制ログアウトしました。");
                state.last_focus = handles.login_name_edit;
                Some((clear_args, Some(handles.login_name_edit)))
            }
        }
    })
    .flatten();

    if let Some((clear_args, focus_target)) = post {
        apply_clear_main_controls(clear_args);
        if let Some(target) = focus_target {
            focus_control(target);
        }
    }
}

fn handle_exit_request(hwnd: HWND) {
    let snapshot = with_state(|s| (s.app_state, s.dpi, s.modal_open));
    let Some((app_state, dpi, modal_open)) = snapshot else {
        unsafe { DestroyWindow(hwnd) };
        return;
    };
    if modal_open {
        return;
    }

    match app_state {
        AppStateKind::LoggedOut | AppStateKind::Authenticating => {
            let send_err =
                with_state(|s| s.cmd_tx.try_send(UiCommand::Shutdown).is_err()).unwrap_or(true);
            if send_err {
                unsafe { DestroyWindow(hwnd) };
            }
        }
        AppStateKind::LoggedIn | AppStateKind::Locked => {
            let reserved = with_state_mut(|s| {
                if s.modal_open
                    || !matches!(s.app_state, AppStateKind::LoggedIn | AppStateKind::Locked)
                {
                    return false;
                }
                s.modal_open = true;
                true
            })
            .unwrap_or(false);
            if !reserved {
                return;
            }
            let confirmed = confirm_logout_or_exit(hwnd, true, dpi);
            let post = with_ui_and_state_mut(|handles, state| {
                state.modal_open = false;
                if !confirmed
                    || !matches!(
                        state.app_state,
                        AppStateKind::LoggedIn | AppStateKind::Locked
                    )
                {
                    return None;
                }
                match state.cmd_tx.try_send(UiCommand::Shutdown) {
                    Ok(()) => {
                        state.app_state = AppStateKind::LoggingOut;
                        Some((extract_clear_main_args(handles, state), false))
                    }
                    Err(_) => {
                        let args = extract_clear_main_args(handles, state);
                        state.app_state = AppStateKind::Exiting;
                        remove_tray_icon(hwnd, &mut state.tray_icon_added);
                        state.clear_session_fields();
                        Some((args, true))
                    }
                }
            })
            .flatten();
            if let Some((clear_args, destroy_now)) = post {
                apply_clear_main_controls(clear_args);
                if destroy_now {
                    unsafe { DestroyWindow(hwnd) };
                }
            }
        }
        AppStateKind::LoggingOut | AppStateKind::Exiting => {}
    }
}

fn apply_dpi_change(hwnd: HWND, new_dpi: u32, suggested: &RECT) {
    with_ui_and_state_mut(|handles, state| {
        state.dpi = new_dpi;
        let old_fonts = handles.theme.rebuild_fonts_for_dpi(new_dpi);
        unsafe {
            SendMessageW(
                handles.login_title,
                WM_SETFONT,
                handles.theme.bold_font as usize,
                1,
            );
            SendMessageW(
                handles.main_thread_header,
                WM_SETFONT,
                handles.theme.bold_font as usize,
                1,
            );
            SendMessageW(
                handles.lock_title,
                WM_SETFONT,
                handles.theme.bold_font as usize,
                1,
            );
            for ctrl in handles.all_ui_font_controls() {
                SendMessageW(ctrl, WM_SETFONT, handles.theme.ui_font as usize, 1);
            }
            ThemeResources::delete_fonts(old_fonts);
            SetWindowPos(
                hwnd,
                null_mut(),
                suggested.left,
                suggested.top,
                suggested.right - suggested.left,
                suggested.bottom - suggested.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
        let mut rc: RECT = unsafe { zeroed() };
        unsafe { GetClientRect(hwnd, &raw mut rc) };
        let cw = rc.right - rc.left;
        let ch = rc.bottom - rc.top;
        layout_login_controls(handles, cw, ch, new_dpi);
        layout_main_controls(handles, cw, ch, new_dpi);
        layout_lock_controls(handles, cw, ch, new_dpi);
    });
}

unsafe extern "system" fn main_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    guard_wnd_proc(0, || unsafe {
        match msg {
            WM_CREATE => {
                if lparam == 0 {
                    return -1;
                }
                let cs = &*(lparam as *const CREATESTRUCTW);
                if cs.lpCreateParams.is_null() {
                    return -1;
                }
                let pending_slot = &mut *(cs.lpCreateParams as *mut Option<PendingWindowInit>);
                let Some(init_box) = pending_slot.take() else {
                    return -1;
                };
                let hinst = GetModuleHandleW(null());
                let dpi = GetDpiForWindow(hwnd).max(96);
                let high_contrast = is_high_contrast();

                let theme = ThemeResources::new(dpi);
                theme.apply_icons_to_window(hwnd);
                apply_window_dwm_attributes(hwnd);

                let menu = create_main_menu_bar();
                sync_menu_enabled_state(menu.bar, AppStateKind::LoggedOut);
                sync_option_menu_checks(menu.bar, &init_box.config);

                let login_ctrls =
                    create_login_controls(hwnd, hinst, theme.ui_font, theme.bold_font);
                let main_ctrls = create_main_controls(
                    hwnd,
                    hinst,
                    theme.ui_font,
                    theme.bold_font,
                    high_contrast,
                );
                let lock_ctrls = create_lock_controls(hwnd, hinst, theme.ui_font, theme.bold_font);
                set_input_send_on_enter(main_ctrls.input_edit, init_box.config.send_on_enter);

                let (event_tx, event_rx) = std::sync::mpsc::channel();
                let hwnd_raw = hwnd as usize;
                let alive_flag = Arc::clone(&init_box.window_alive);
                let wake_ui: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                    if alive_flag.load(Ordering::SeqCst) {
                        let _ = PostMessageW(hwnd_raw as HWND, WM_APP_EVENT, 0, 0);
                    }
                });
                let app_handle = {
                    let _enter = init_box.runtime_handle.enter();
                    spawn_coordinator(
                        CoordinatorOptions::production(init_box.paths.clone()),
                        event_tx,
                        wake_ui,
                    )
                };

                let handles = UiHandles {
                    hmenu_main: menu.bar,
                    hmenu_status: menu.status_sub,
                    theme,
                    login_title: login_ctrls.title,
                    login_subtitle: login_ctrls.subtitle,
                    login_name_label: login_ctrls.name_label,
                    login_name_edit: login_ctrls.name_edit,
                    login_pass_label: login_ctrls.pass_label,
                    login_pass_edit: login_ctrls.pass_edit,
                    login_pass_guide: login_ctrls.pass_guide,
                    login_show_pass: login_ctrls.show_pass,
                    login_submit: login_ctrls.submit,
                    login_cancel: login_ctrls.cancel,
                    login_options: login_ctrls.options,
                    login_status: login_ctrls.status,
                    main_peer_label: main_ctrls.peer_label,
                    main_peer_list: main_ctrls.peer_list,
                    main_thread_header: main_ctrls.thread_header,
                    main_notice: main_ctrls.notice,
                    main_chat_list: main_ctrls.chat_list,
                    main_byte_guide: main_ctrls.byte_guide,
                    main_input_edit: main_ctrls.input_edit,
                    main_send_btn: main_ctrls.send_btn,
                    main_file_btn: main_ctrls.file_btn,
                    main_statusbar: main_ctrls.statusbar,
                    lock_title: lock_ctrls.title,
                    lock_guide: lock_ctrls.guide,
                    lock_pass_label: lock_ctrls.pass_label,
                    lock_pass_edit: lock_ctrls.pass_edit,
                    lock_unlock_btn: lock_ctrls.unlock_btn,
                    lock_logout_btn: lock_ctrls.logout_btn,
                    lock_status: lock_ctrls.status,
                };
                let state = UiState {
                    app_state: AppStateKind::LoggedOut,
                    paths: init_box.paths,
                    config: init_box.config,
                    cmd_tx: app_handle.cmd_tx,
                    log_reader: app_handle.log_reader,
                    event_rx,
                    active_thread: ThreadKey::Broadcast,
                    peers: Vec::new(),
                    display_name: String::new(),
                    room_code: String::new(),
                    ephemeral_peer_id: String::new(),
                    tcp_port: 0,
                    udp_port: 0,
                    nic_info: None,
                    status: UserStatus::Online,
                    total_log_bytes: 0,
                    last_lv_count: 0,
                    notice_text: String::new(),
                    dpi,
                    high_contrast,
                    modal_open: false,
                    last_focus: handles.login_name_edit,
                    window_alive: init_box.window_alive,
                    multi_instance: init_box.multi_instance,
                    sound: SoundController::new(),
                    broadcast_unread_count: 0,
                    unread_by_peer: HashMap::new(),
                    last_search_query: Zeroizing::new(String::new()),
                    auto_away_triggered: false,
                    tray_icon_added: false,
                    active_transfer: None,
                    pending_file_offers: VecDeque::new(),
                };
                if let Ok(mut slot) = init_box.join_slot.lock() {
                    *slot = Some(app_handle.join_handle);
                }

                let mut rc: RECT = zeroed();
                GetClientRect(hwnd, &raw mut rc);
                layout_login_controls(&handles, rc.right - rc.left, rc.bottom - rc.top, dpi);
                layout_main_controls(&handles, rc.right - rc.left, rc.bottom - rc.top, dpi);
                layout_lock_controls(&handles, rc.right - rc.left, rc.bottom - rc.top, dpi);
                show_main_controls(&handles, false);
                show_lock_controls(&handles, false);
                show_login_controls(&handles, true);
                init_thread_locals(handles, state);
                SetTimer(hwnd, TIMER_AUTO_AWAY, 10_000, None);
                0
            }
            WM_SIZE => {
                let cw = (lparam & 0xFFFF) as i16 as i32;
                let ch = ((lparam >> 16) & 0xFFFF) as i16 as i32;
                with_ui_and_state(|handles, state| {
                    layout_login_controls(handles, cw, ch, state.dpi);
                    layout_main_controls(handles, cw, ch, state.dpi);
                    layout_lock_controls(handles, cw, ch, state.dpi);
                });
                0
            }
            WM_TIMER => {
                if wparam == TIMER_AUTO_AWAY {
                    let mut lii = LASTINPUTINFO {
                        cbSize: size_of::<LASTINPUTINFO>() as u32,
                        dwTime: 0,
                    };
                    if GetLastInputInfo(&raw mut lii) != 0 {
                        let idle_ms = GetTickCount().wrapping_sub(lii.dwTime);
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state != AppStateKind::LoggedIn {
                                return;
                            }
                            let mins = state.config.auto_away_minutes;
                            if mins == 0 {
                                return;
                            }
                            let threshold_ms = u32::from(mins).saturating_mul(60_000);
                            if idle_ms >= threshold_ms && state.status == UserStatus::Online {
                                state.auto_away_triggered = true;
                                state.status = UserStatus::Away;
                                sync_status_menu_check(handles.hmenu_status, UserStatus::Away);
                                update_status_bar(handles, state);
                                let _ = state
                                    .cmd_tx
                                    .try_send(UiCommand::ChangeStatus(UserStatus::Away));
                            } else if idle_ms < 15_000
                                && state.auto_away_triggered
                                && state.status == UserStatus::Away
                            {
                                state.auto_away_triggered = false;
                                state.status = UserStatus::Online;
                                sync_status_menu_check(handles.hmenu_status, UserStatus::Online);
                                update_status_bar(handles, state);
                                let _ = state
                                    .cmd_tx
                                    .try_send(UiCommand::ChangeStatus(UserStatus::Online));
                            }
                        });
                    }
                }
                0
            }
            WM_GETMINMAXINFO => {
                if lparam == 0 {
                    return 0;
                }
                let dpi = with_state(|s| s.dpi).unwrap_or(96);
                let mmi = &mut *(lparam as *mut MINMAXINFO);
                mmi.ptMinTrackSize.x = scale_dpi(720, dpi);
                mmi.ptMinTrackSize.y = scale_dpi(500, dpi);
                0
            }
            WM_DPICHANGED => {
                if lparam == 0 {
                    return 0;
                }
                let new_dpi = (wparam & 0xFFFF) as u32;
                let suggested = &*(lparam as *const RECT);
                apply_dpi_change(hwnd, new_dpi.max(96), suggested);
                0
            }
            WM_SETTINGCHANGE | WM_THEMECHANGED => {
                let hc = is_high_contrast();
                with_ui_and_state_mut(|handles, state| {
                    state.high_contrast = hc;
                    apply_listview_explorer_theme(handles.main_chat_list, hc);
                    let _ = InvalidateRect(hwnd, null(), 1);
                });
                0
            }
            WM_CTLCOLORSTATIC => {
                let target = lparam as HWND;
                let custom = with_ui_and_state(|handles, state| {
                    if target == handles.main_notice
                        && !state.high_contrast
                        && !state.notice_text.is_empty()
                    {
                        let hdc = wparam as windows_sys::Win32::Graphics::Gdi::HDC;
                        SetTextColor(hdc, CLR_NOTICE_TEXT);
                        SetBkColor(hdc, theme::CLR_NOTICE_BG);
                        Some(handles.theme.notice_bg_brush as LRESULT)
                    } else {
                        None
                    }
                })
                .flatten();
                if let Some(brush) = custom {
                    return brush;
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_ACTIVATE => {
                if (wparam & 0xFFFF) as u32 != WA_INACTIVE {
                    let focus_target = with_ui_and_state_mut(|handles, state| {
                        if state.modal_open {
                            return None;
                        }
                        if state.app_state == AppStateKind::LoggedIn {
                            let active = state.active_thread.clone();
                            if clear_unread_for_thread(state, &active) {
                                refresh_peer_list(handles, state);
                            }
                        }
                        let cur = GetFocus();
                        if cur.is_null() || cur == hwnd {
                            Some(match state.app_state {
                                AppStateKind::LoggedOut => handles.login_name_edit,
                                AppStateKind::Authenticating => handles.login_cancel,
                                AppStateKind::LoggedIn => {
                                    if !state.last_focus.is_null() {
                                        state.last_focus
                                    } else {
                                        handles.main_input_edit
                                    }
                                }
                                AppStateKind::Locked => handles.lock_pass_edit,
                                AppStateKind::LoggingOut | AppStateKind::Exiting => null_mut(),
                            })
                        } else {
                            None
                        }
                    })
                    .flatten();
                    if let Some(target) = focus_target {
                        focus_control(target);
                    }
                }
                0
            }
            WM_COMMAND => {
                let id = wparam & 0xFFFF;
                let code = ((wparam >> 16) & 0xFFFF) as u32;
                match id {
                    IDC_LOGIN_PASS_EDIT if code == EN_CHANGE => {
                        with_ui(update_password_guide);
                        return 0;
                    }
                    IDC_LOGIN_SHOW_PASS if code == BN_CLICKED => {
                        with_ui(toggle_password_visibility);
                        return 0;
                    }
                    IDC_LOGIN_SUBMIT if code == BN_CLICKED => {
                        submit_login();
                        return 0;
                    }
                    IDC_LOGIN_CANCEL if code == BN_CLICKED => {
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::Authenticating {
                                let _ = state.cmd_tx.try_send(UiCommand::CancelLogin);
                                set_login_status_message(
                                    handles,
                                    "ログインをキャンセルしています...",
                                );
                            }
                        });
                        return 0;
                    }
                    IDC_LOGIN_OPTIONS | IDM_OPTIONS => {
                        handle_options_modal(hwnd);
                        return 0;
                    }
                    IDC_MAIN_PEER_LIST if code == LBN_SELCHANGE => {
                        handle_peer_list_selchange();
                        return 0;
                    }
                    IDC_MAIN_INPUT_EDIT if code == EN_CHANGE => {
                        with_ui_and_state(|handles, state| {
                            update_input_byte_guide(handles, state.config.send_on_enter);
                        });
                        return 0;
                    }
                    IDC_MAIN_SEND_BTN if code == BN_CLICKED => {
                        send_current_input();
                        return 0;
                    }
                    IDC_MAIN_FILE_BTN if code == BN_CLICKED => {
                        handle_file_button_clicked(hwnd);
                        return 0;
                    }
                    IDC_LOCK_UNLOCK_BTN if code == BN_CLICKED => {
                        submit_unlock();
                        return 0;
                    }
                    IDC_LOCK_LOGOUT_BTN if code == BN_CLICKED => {
                        handle_logout_request(hwnd);
                        return 0;
                    }
                    IDM_STATUS_ONLINE | IDM_STATUS_AWAY | IDM_STATUS_BUSY => {
                        let next_status = match id {
                            IDM_STATUS_AWAY => UserStatus::Away,
                            IDM_STATUS_BUSY => UserStatus::Busy,
                            _ => UserStatus::Online,
                        };
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::LoggedIn {
                                state.auto_away_triggered = false;
                                state.status = next_status;
                                sync_status_menu_check(handles.hmenu_status, next_status);
                                update_status_bar(handles, state);
                                let _ = state.cmd_tx.try_send(UiCommand::ChangeStatus(next_status));
                            }
                        });
                        return 0;
                    }
                    IDM_LOCK_SCREEN => {
                        with_state(|state| {
                            if state.app_state == AppStateKind::LoggedIn && !state.modal_open {
                                let _ = state.cmd_tx.try_send(UiCommand::LockScreen);
                            }
                        });
                        return 0;
                    }
                    IDM_SEARCH => {
                        handle_search_modal(hwnd);
                        return 0;
                    }
                    IDM_TOGGLE_SOUND => {
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::Locked {
                                return;
                            }
                            state.config.sound_enabled = !state.config.sound_enabled;
                            let next = state.config.clone();
                            sync_option_menu_checks(handles.hmenu_main, &next);
                            let _ = state.cmd_tx.try_send(UiCommand::UpdateConfig(next));
                        });
                        return 0;
                    }
                    IDM_TOGGLE_SEND_ON_ENTER => {
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::Locked {
                                return;
                            }
                            state.config.send_on_enter = !state.config.send_on_enter;
                            let next = state.config.clone();
                            set_input_send_on_enter(handles.main_input_edit, next.send_on_enter);
                            update_input_byte_guide(handles, next.send_on_enter);
                            sync_option_menu_checks(handles.hmenu_main, &next);
                            let _ = state.cmd_tx.try_send(UiCommand::UpdateConfig(next));
                        });
                        return 0;
                    }
                    IDM_LOGOUT => {
                        handle_logout_request(hwnd);
                        return 0;
                    }
                    IDM_EXIT => {
                        handle_exit_request(hwnd);
                        return 0;
                    }
                    IDM_SHOW_DETAIL => {
                        open_selected_message_detail(hwnd);
                        return 0;
                    }
                    IDM_RETRY_SELECTED => {
                        retry_selected_message();
                        return 0;
                    }
                    IDM_CLEAR_CURRENT => {
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::LoggedIn {
                                let thread = state.active_thread.clone();
                                let _ = state.cmd_tx.try_send(UiCommand::ClearSessionChat {
                                    thread: Some(thread),
                                });
                                set_notice_text(
                                    handles,
                                    state,
                                    "現在表示中の会話ログを消去しました。",
                                );
                            }
                        });
                        return 0;
                    }
                    IDM_CLEAR_ALL => {
                        with_ui_and_state_mut(|handles, state| {
                            if state.app_state == AppStateKind::LoggedIn {
                                let _ = state
                                    .cmd_tx
                                    .try_send(UiCommand::ClearSessionChat { thread: None });
                                set_notice_text(
                                    handles,
                                    state,
                                    "全スレッドの会話ログを消去しました。",
                                );
                            }
                        });
                        return 0;
                    }
                    IDM_SEND_FILE => {
                        start_send_file_flow(hwnd);
                        return 0;
                    }
                    IDM_CANCEL_FILE_TRANSFER => {
                        cancel_active_file_transfer();
                        return 0;
                    }
                    IDM_ADD_MANUAL_PEER => {
                        handle_manual_peer_modal(hwnd);
                        return 0;
                    }
                    IDM_REFRESH_NETWORK => {
                        with_state(|state| {
                            if state.app_state == AppStateKind::LoggedIn {
                                let _ = state.cmd_tx.try_send(UiCommand::RefreshNetwork);
                            }
                        });
                        return 0;
                    }
                    IDM_CONN_INFO => {
                        run_guarded_modal(
                            hwnd,
                            |s| {
                                (s.app_state == AppStateKind::LoggedIn)
                                    .then(|| (build_connection_info_text(s), s.dpi))
                            },
                            |(text, dpi)| show_connection_info_dialog(hwnd, &text, dpi),
                            |_, _, _| {},
                            |()| {},
                        );
                        return 0;
                    }
                    IDM_SHORTCUTS => {
                        run_guarded_modal(
                            hwnd,
                            |s| Some(s.dpi),
                            |dpi| show_shortcuts_dialog(hwnd, dpi),
                            |_, _, _| {},
                            |()| {},
                        );
                        return 0;
                    }
                    IDM_ABOUT => {
                        run_guarded_modal(
                            hwnd,
                            |s| Some(s.dpi),
                            |dpi| show_about_dialog(hwnd, dpi),
                            |_, _, _| {},
                            |()| {},
                        );
                        return 0;
                    }
                    _ => {}
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_NOTIFY => {
                if lparam != 0 {
                    let hdr = &*(lparam as *const windows_sys::Win32::UI::Controls::NMHDR);
                    if hdr.idFrom == IDC_MAIN_CHAT_LIST {
                        if hdr.code == windows_sys::Win32::UI::Controls::LVN_GETDISPINFOW {
                            with_state(|state| handle_lv_getdispinfo(lparam, state));
                            return 0;
                        }
                        if hdr.code == windows_sys::Win32::UI::Controls::LVN_ITEMACTIVATE {
                            let act = &*(lparam
                                as *const windows_sys::Win32::UI::Controls::NMITEMACTIVATE);
                            if act.iItem >= 0 {
                                PostMessageW(hwnd, WM_APP_OPEN_DETAIL, 0, 0);
                            }
                            return 0;
                        }
                    }
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            WM_APP_EVENT => {
                drain_app_events(hwnd);
                0
            }
            WM_APP_OPEN_DETAIL => {
                open_selected_message_detail(hwnd);
                0
            }
            WM_CLOSE => {
                handle_exit_request(hwnd);
                0
            }
            WM_DESTROY => {
                KillTimer(hwnd, TIMER_AUTO_AWAY);
                with_ui_and_state_mut(|handles, state| {
                    state.window_alive.store(false, Ordering::SeqCst);
                    remove_tray_icon(hwnd, &mut state.tray_icon_added);
                    remove_main_subclasses(handles);
                    SetMenu(hwnd, null_mut());
                    if !handles.hmenu_main.is_null() {
                        DestroyMenu(handles.hmenu_main);
                        handles.hmenu_main = null_mut();
                    }
                });
                clear_thread_locals();
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    })
}

pub(crate) fn run_app(
    paths: AppPaths,
    initial_config: LocalConfig,
    multi_instance: bool,
    startup_notice: Option<String>,
    runtime: &tokio::runtime::Runtime,
) -> i32 {
    let class_name = to_wide("ZeroHopMainWindowClass");
    let hinst = unsafe { GetModuleHandleW(null()) };

    let mut wc: WNDCLASSEXW = unsafe { zeroed() };
    wc.cbSize = size_of::<WNDCLASSEXW>() as u32;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = Some(main_wnd_proc);
    wc.hInstance = hinst;
    wc.hCursor = unsafe { LoadCursorW(null_mut(), IDC_ARROW) };
    wc.hbrBackground = unsafe { GetSysColorBrush(COLOR_BTNFACE) };
    wc.lpszClassName = class_name.as_ptr();
    unsafe {
        if RegisterClassExW(&raw const wc) == 0 && GetLastError() != 0 {
            return 1;
        }
    }

    let window_alive = Arc::new(AtomicBool::new(true));
    let join_slot = Arc::new(std::sync::Mutex::new(None));
    let mut pending = Some(PendingWindowInit {
        paths,
        config: initial_config,
        multi_instance,
        window_alive: Arc::clone(&window_alive),
        runtime_handle: runtime.handle().clone(),
        join_slot: Arc::clone(&join_slot),
    });

    let sys_dpi = unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForSystem() }.max(96);
    let init_w = scale_dpi(960, sys_dpi);
    let init_h = scale_dpi(660, sys_dpi);
    let (pos_x, pos_y) = center_rect_on_cursor_monitor(init_w, init_h);
    let title = if multi_instance {
        to_wide("ZeroHop [マルチ起動]")
    } else {
        to_wide("ZeroHop")
    };

    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            pos_x,
            pos_y,
            init_w,
            init_h,
            null_mut(),
            null_mut(),
            hinst,
            (&raw mut pending).cast(),
        )
    };
    drop(pending);
    if hwnd.is_null() {
        return 1;
    }

    if let Some(msg_text) = startup_notice {
        with_ui(|handles| set_login_status_message(handles, &msg_text));
    }

    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        with_ui(|handles| focus_control(handles.login_name_edit));

        let mut msg: MSG = zeroed();
        while GetMessageW(&raw mut msg, null_mut(), 0, 0) > 0 {
            if !handle_global_shortcut(hwnd, &msg) && IsDialogMessageW(hwnd, &raw const msg) == 0 {
                TranslateMessage(&raw const msg);
                DispatchMessageW(&raw const msg);
            }
            with_ui_and_state_mut(|handles, state| {
                let focus = GetFocus();
                if state.app_state == AppStateKind::LoggedIn
                    && (focus == handles.main_peer_list
                        || focus == handles.main_chat_list
                        || focus == handles.main_input_edit)
                {
                    state.last_focus = focus;
                }
            });
        }
    }

    window_alive.store(false, Ordering::SeqCst);
    clear_thread_locals();
    let pending_join = join_slot.lock().ok().and_then(|mut g| g.take());
    if let Some(jh) = pending_join {
        let _ = runtime.block_on(jh);
    }
    0
}
