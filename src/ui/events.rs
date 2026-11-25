//! AppEvent 受信処理・トレイバルーン通知。

use std::ptr::null_mut;
use std::time::Instant;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::EM_SETSEL;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIIF_NOSOUND, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, FLASHW_TIMERNOFG, FLASHW_TRAY, FLASHWINFO, FlashWindowEx, GetForegroundWindow,
    IDI_APPLICATION, IsIconic, LoadIconW, SendMessageW, SetMenu, SetWindowTextW,
};

use zerohop::app::state::{AppEvent, AppStateKind};
use zerohop::domain::model::ThreadKey;

use super::a11y::focus_control;
use super::lock_view::show_lock_controls;
use super::login_view::{
    reset_login_form, set_authenticating_ui, set_login_status_message, show_login_controls,
};
use super::main_view::{
    LvSyncArgs, apply_clear_main_controls, apply_virtual_listview_sync, clear_unread_for_thread,
    extract_clear_main_args, prepare_virtual_listview_sync, refresh_peer_list,
    set_input_send_on_enter, set_notice_text, show_main_controls, update_input_byte_guide,
    update_status_bar,
};
use super::menu_bar::{sync_menu_enabled_state, sync_option_menu_checks, sync_status_menu_check};
use super::sound::{SoundEvent, play_logout_on_exit_sync, play_sound_if_allowed};
use super::state_helpers::{
    ActiveUiTransfer, PendingUiFileOffer, with_state, with_state_mut, with_ui_and_state_mut,
};
use super::transfer_ui::{process_pending_file_offers, sync_file_transfer_button};
use super::{WM_APP_TRAY_CALLBACK, format_bytes_human, to_wide, write_utf16_buf};

const TRAY_ICON_ID: u32 = 1;

pub(crate) fn is_window_foreground(hwnd: HWND) -> bool {
    unsafe { GetForegroundWindow() == hwnd && IsIconic(hwnd) == 0 }
}

pub(crate) fn remove_tray_icon(hwnd: HWND, tray_icon_added: &mut bool) {
    if !*tray_icon_added || hwnd.is_null() {
        return;
    }
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    unsafe {
        Shell_NotifyIconW(NIM_DELETE, &raw const nid);
    }
    *tray_icon_added = false;
}

fn show_balloon_notification(hwnd: HWND, tray_icon_added: &mut bool, title: &str, body: &str) {
    if hwnd.is_null() {
        return;
    }
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uCallbackMessage = WM_APP_TRAY_CALLBACK;

    if !*tray_icon_added {
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.hIcon = unsafe { LoadIconW(null_mut(), IDI_APPLICATION) };
        write_utf16_buf(nid.szTip.as_mut_ptr(), nid.szTip.len() as i32, "ZeroHop");
        unsafe {
            if Shell_NotifyIconW(NIM_ADD, &raw const nid) != 0 {
                *tray_icon_added = true;
            }
        }
    }

    if *tray_icon_added {
        nid.uFlags = NIF_INFO;
        nid.dwInfoFlags = NIIF_INFO | NIIF_NOSOUND;
        write_utf16_buf(
            nid.szInfoTitle.as_mut_ptr(),
            nid.szInfoTitle.len() as i32,
            title,
        );
        write_utf16_buf(nid.szInfo.as_mut_ptr(), nid.szInfo.len() as i32, body);
        unsafe {
            Shell_NotifyIconW(NIM_MODIFY, &raw const nid);
        }
    }

    let fw = FLASHWINFO {
        cbSize: std::mem::size_of::<FLASHWINFO>() as u32,
        hwnd,
        dwFlags: FLASHW_TRAY | FLASHW_TIMERNOFG,
        uCount: 3,
        dwTimeout: 0,
    };
    unsafe {
        FlashWindowEx(&raw const fw);
    }
}

pub(crate) fn drain_app_events(hwnd: HWND) {
    let events: Vec<AppEvent> =
        with_state(|state| state.event_rx.try_iter().collect()).unwrap_or_default();
    for ev in events {
        match ev {
            AppEvent::LoginSucceeded {
                display_name,
                room_code,
                ephemeral_peer_id,
                tcp_port,
                udp_port,
                nic_info,
            } => {
                let post = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::LoggedIn;
                    state.display_name = display_name;
                    state.room_code = room_code;
                    state.ephemeral_peer_id = ephemeral_peer_id;
                    state.tcp_port = tcp_port;
                    state.udp_port = udp_port;
                    state.nic_info = nic_info;
                    state.status = zerohop::domain::model::UserStatus::Online;
                    state.active_thread = ThreadKey::Broadcast;
                    state.peers.clear();
                    state.total_log_bytes = 0;
                    state.last_lv_count = 0;

                    set_authenticating_ui(handles, false);
                    reset_login_form(handles, false);
                    show_login_controls(handles, false);
                    show_lock_controls(handles, false);
                    unsafe {
                        SetMenu(hwnd, handles.hmenu_main);
                        windows_sys::Win32::UI::WindowsAndMessaging::DrawMenuBar(hwnd);
                    }
                    sync_menu_enabled_state(handles.hmenu_main, AppStateKind::LoggedIn);
                    sync_status_menu_check(handles.hmenu_status, state.status);
                    sync_option_menu_checks(handles.hmenu_main, &state.config);
                    set_input_send_on_enter(handles.main_input_edit, state.config.send_on_enter);
                    show_main_controls(handles, true);
                    refresh_peer_list(handles, state);
                    sync_file_transfer_button(handles, state);
                    let lv = prepare_virtual_listview_sync(handles, state, true);
                    update_input_byte_guide(handles, state.config.send_on_enter);
                    set_notice_text(handles, state, "");
                    state.last_focus = handles.main_input_edit;
                    state.sound.mark_login_at(Instant::now());
                    play_sound_if_allowed(
                        &mut state.sound,
                        SoundEvent::Login,
                        &state.config,
                        false,
                    );
                    (lv, handles.main_input_edit)
                });
                if let Some((lv, focus_target)) = post {
                    apply_virtual_listview_sync(lv);
                    focus_control(focus_target);
                }
            }
            AppEvent::LoginFailed { reason } => {
                let focus_target = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::LoggedOut;
                    set_authenticating_ui(handles, false);
                    set_login_status_message(handles, &reason);
                    handles.login_pass_edit
                });
                if let Some(target) = focus_target {
                    focus_control(target);
                }
            }
            AppEvent::PeerListChanged(new_peers) => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if !matches!(
                        state.app_state,
                        AppStateKind::LoggedIn | AppStateKind::Locked
                    ) || state.peers == new_peers
                    {
                        return None;
                    }
                    state.peers = new_peers;
                    if state.app_state == AppStateKind::Locked {
                        return None;
                    }
                    let thread_changed = refresh_peer_list(handles, state);
                    sync_file_transfer_button(handles, state);
                    if thread_changed {
                        state.last_lv_count = 0;
                        Some(prepare_virtual_listview_sync(handles, state, true))
                    } else {
                        None
                    }
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::PeerJoined { .. } => {
                with_state_mut(|state| {
                    let is_locked = state.app_state == AppStateKind::Locked;
                    play_sound_if_allowed(
                        &mut state.sound,
                        SoundEvent::PeerJoined,
                        &state.config,
                        is_locked,
                    );
                });
            }
            AppEvent::PeerLeft { .. } => {
                with_state_mut(|state| {
                    let is_locked = state.app_state == AppStateKind::Locked;
                    play_sound_if_allowed(
                        &mut state.sound,
                        SoundEvent::PeerLeft,
                        &state.config,
                        is_locked,
                    );
                });
            }
            AppEvent::IncomingMessageReceived {
                thread,
                sender_name,
                preview,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if !matches!(
                        state.app_state,
                        AppStateKind::LoggedIn | AppStateKind::Locked
                    ) {
                        return;
                    }
                    let is_locked = state.app_state == AppStateKind::Locked;
                    let fg = !is_locked && is_window_foreground(hwnd);
                    let is_active_fg = fg && state.active_thread == thread;

                    if !is_active_fg {
                        match &thread {
                            ThreadKey::Broadcast => {
                                state.broadcast_unread_count =
                                    state.broadcast_unread_count.saturating_add(1);
                            }
                            ThreadKey::Peer(pid) => {
                                let cnt = state.unread_by_peer.entry(pid.clone()).or_insert(0);
                                *cnt = cnt.saturating_add(1);
                            }
                        }
                    }

                    if !is_locked {
                        refresh_peer_list(handles, state);
                        play_sound_if_allowed(
                            &mut state.sound,
                            SoundEvent::MessageReceived,
                            &state.config,
                            false,
                        );
                        if !fg {
                            let (title, body) = if state.config.hide_notification_preview {
                                (
                                    "ZeroHop".to_string(),
                                    "新着メッセージがあります".to_string(),
                                )
                            } else {
                                (format!("新着メッセージ: {sender_name}"), preview)
                            };
                            show_balloon_notification(
                                hwnd,
                                &mut state.tray_icon_added,
                                &title,
                                &body,
                            );
                        }
                    }
                });
            }
            AppEvent::ScreenLocked => {
                let post = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::Locked;
                    remove_tray_icon(hwnd, &mut state.tray_icon_added);
                    show_main_controls(handles, false);
                    sync_menu_enabled_state(handles.hmenu_main, AppStateKind::Locked);
                    unsafe {
                        let empty = to_wide("");
                        SetWindowTextW(handles.lock_pass_edit, empty.as_ptr());
                        SetWindowTextW(handles.lock_status, empty.as_ptr());
                        EnableWindow(handles.lock_pass_edit, 1);
                        EnableWindow(handles.lock_unlock_btn, 1);
                        EnableWindow(handles.lock_logout_btn, 1);
                    }
                    show_lock_controls(handles, true);
                    state.last_lv_count = 0;
                    state.last_focus = handles.lock_pass_edit;
                    (
                        LvSyncArgs {
                            hwnd_lv: handles.main_chat_list,
                            prev_count: 0,
                            new_count: 0,
                            allow_autoscroll: false,
                        },
                        handles.lock_pass_edit,
                    )
                });
                if let Some((lv, focus_target)) = post {
                    apply_virtual_listview_sync(lv);
                    focus_control(focus_target);
                }
            }
            AppEvent::ScreenUnlockResult { ok } => {
                if ok {
                    let post = with_ui_and_state_mut(|handles, state| {
                        state.app_state = AppStateKind::LoggedIn;
                        unsafe {
                            let empty = to_wide("");
                            SetWindowTextW(handles.lock_pass_edit, empty.as_ptr());
                            SetWindowTextW(handles.lock_status, empty.as_ptr());
                        }
                        show_lock_controls(handles, false);
                        sync_menu_enabled_state(handles.hmenu_main, AppStateKind::LoggedIn);
                        show_main_controls(handles, true);
                        let active_clone = state.active_thread.clone();
                        clear_unread_for_thread(state, &active_clone);
                        state.total_log_bytes = state.log_reader.total_bytes();
                        refresh_peer_list(handles, state);
                        sync_file_transfer_button(handles, state);
                        update_input_byte_guide(handles, state.config.send_on_enter);
                        let lv = prepare_virtual_listview_sync(handles, state, true);
                        state.last_focus = handles.main_input_edit;
                        (lv, handles.main_input_edit)
                    });
                    if let Some((lv, focus_target)) = post {
                        apply_virtual_listview_sync(lv);
                        focus_control(focus_target);
                    }
                    process_pending_file_offers(hwnd);
                } else {
                    let target = with_ui_and_state_mut(|handles, state| {
                        if state.app_state != AppStateKind::Locked {
                            return None;
                        }
                        let msg = to_wide(
                            "パスワードが一致しません。再入力するか「ログアウトして全消去」を選択してください。",
                        );
                        unsafe {
                            EnableWindow(handles.lock_pass_edit, 1);
                            EnableWindow(handles.lock_unlock_btn, 1);
                            EnableWindow(handles.lock_logout_btn, 1);
                            SetWindowTextW(handles.lock_status, msg.as_ptr());
                            SendMessageW(handles.lock_pass_edit, EM_SETSEL, 0, -1);
                        }
                        Some(handles.lock_pass_edit)
                    })
                    .flatten();
                    if let Some(hwnd_pass) = target {
                        focus_control(hwnd_pass);
                    }
                }
            }
            AppEvent::ThreadUpdated {
                thread,
                total_log_bytes,
                ..
            } => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return None;
                    }
                    state.total_log_bytes = total_log_bytes;
                    let actual_len = state.log_reader.thread_len(&state.active_thread);
                    let lv = if state.active_thread == thread || actual_len != state.last_lv_count {
                        Some(prepare_virtual_listview_sync(
                            handles,
                            state,
                            state.active_thread == thread,
                        ))
                    } else {
                        None
                    };
                    update_status_bar(handles, state);
                    lv
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::DeliveryUpdated { thread, .. } => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return None;
                    }
                    state.total_log_bytes = state.log_reader.total_bytes();
                    let lv = if state.active_thread == thread {
                        Some(prepare_virtual_listview_sync(handles, state, false))
                    } else {
                        None
                    };
                    update_status_bar(handles, state);
                    lv
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::NetworkRefreshed {
                nic_info,
                tcp_port,
                udp_port,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    state.nic_info = nic_info;
                    state.tcp_port = tcp_port;
                    state.udp_port = udp_port;
                    update_status_bar(handles, state);
                    set_notice_text(handles, state, "ネットワークアダプタ情報を更新しました。");
                });
            }
            AppEvent::StatusChanged(next_status) => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    state.status = next_status;
                    sync_status_menu_check(handles.hmenu_status, next_status);
                    update_status_bar(handles, state);
                });
            }
            AppEvent::KeyMismatchDetected { peer_ip } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【鍵不一致】{peer_ip} からの通信を復号できませんでした。ルームパスワードをご確認ください。"
                        ),
                    );
                });
            }
            AppEvent::ClockSkewDetected {
                peer_ip,
                skew_seconds,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【時刻ズレ】{peer_ip} との時刻差が許容範囲（±5分）を超えています（差: {skew_seconds}秒）。PCの時計同期をご確認ください。"
                        ),
                    );
                });
            }
            AppEvent::ProtocolVersionMismatch {
                peer_ip,
                received_version,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【版数不一致】{peer_ip} から非互換プロトコル v{received_version} の通信を受信しました。"
                        ),
                    );
                });
            }
            AppEvent::FileOfferReceived {
                transfer_id,
                peer_id: _,
                peer_name,
                filename,
                file_size,
                sha256_hex,
            } => {
                let should_process = with_state_mut(|state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return false;
                    }
                    state.pending_file_offers.push_back(PendingUiFileOffer {
                        transfer_id,
                        peer_name,
                        filename,
                        file_size,
                        sha256_hex,
                    });
                    !state.modal_open
                })
                .unwrap_or(false);
                if should_process {
                    process_pending_file_offers(hwnd);
                }
            }
            AppEvent::FileTransferProgress {
                transfer_id,
                peer_id: _,
                filename,
                is_sending,
                transferred_bytes,
                total_bytes,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    state.active_transfer = Some(ActiveUiTransfer { transfer_id });
                    let pct = transferred_bytes
                        .saturating_mul(100)
                        .checked_div(total_bytes)
                        .unwrap_or(0)
                        .min(100);
                    let verb = if is_sending { "送信中" } else { "受信中" };
                    let cur_h = format_bytes_human(transferred_bytes as usize);
                    let tot_h = format_bytes_human(total_bytes as usize);
                    set_notice_text(
                        handles,
                        state,
                        &format!("[{verb}] {filename}: {pct}% ({cur_h} / {tot_h})"),
                    );
                    sync_file_transfer_button(handles, state);
                });
            }
            AppEvent::FileTransferFinished {
                transfer_id,
                peer_id: _,
                filename,
                is_sending: _,
                ok,
                message,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state
                        .active_transfer
                        .as_ref()
                        .is_some_and(|t| t.transfer_id == transfer_id)
                    {
                        state.active_transfer = None;
                    }
                    if state.app_state == AppStateKind::LoggedIn {
                        let prefix = if ok { "完了" } else { "中断" };
                        set_notice_text(
                            handles,
                            state,
                            &format!("[ファイル{prefix}] {filename}: {message}"),
                        );
                        sync_file_transfer_button(handles, state);
                    }
                });
            }
            AppEvent::ErrorNotice(msg) => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state == AppStateKind::LoggedIn {
                        set_notice_text(handles, state, &msg);
                    } else {
                        set_login_status_message(handles, &msg);
                    }
                });
            }
            AppEvent::LogoutCompleted => {
                let post = with_ui_and_state_mut(|handles, state| {
                    let was_locked = state.app_state == AppStateKind::Locked;
                    play_sound_if_allowed(
                        &mut state.sound,
                        SoundEvent::Logout,
                        &state.config,
                        was_locked,
                    );
                    remove_tray_icon(hwnd, &mut state.tray_icon_added);
                    state.app_state = AppStateKind::LoggedOut;
                    let clear_args = extract_clear_main_args(handles, state);
                    state.clear_session_fields();
                    unsafe {
                        let empty = to_wide("");
                        SetWindowTextW(handles.lock_pass_edit, empty.as_ptr());
                        SetWindowTextW(handles.lock_status, empty.as_ptr());
                        SetMenu(hwnd, null_mut());
                        windows_sys::Win32::UI::WindowsAndMessaging::DrawMenuBar(hwnd);
                    }
                    sync_menu_enabled_state(handles.hmenu_main, AppStateKind::LoggedOut);
                    show_lock_controls(handles, false);
                    show_main_controls(handles, false);
                    show_login_controls(handles, true);
                    set_authenticating_ui(handles, false);
                    reset_login_form(handles, false);
                    state.last_focus = handles.login_name_edit;
                    (clear_args, handles.login_name_edit)
                });
                if let Some((clear_args, focus_target)) = post {
                    apply_clear_main_controls(clear_args);
                    focus_control(focus_target);
                }
            }
            AppEvent::ShutdownReady => {
                let exit_info = with_ui_and_state_mut(|handles, state| {
                    let was_locked = state.app_state == AppStateKind::Locked;
                    let cfg = state.config.clone();
                    remove_tray_icon(hwnd, &mut state.tray_icon_added);
                    state.app_state = AppStateKind::Exiting;
                    let args = extract_clear_main_args(handles, state);
                    state.clear_session_fields();
                    (args, cfg, was_locked)
                });
                if let Some((args, cfg, was_locked)) = exit_info {
                    apply_clear_main_controls(args);
                    play_logout_on_exit_sync(&cfg, was_locked);
                }
                unsafe {
                    DestroyWindow(hwnd);
                }
            }
        }
    }
}
