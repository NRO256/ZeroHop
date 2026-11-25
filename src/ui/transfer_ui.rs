//! Phase 3 ファイル転送 UI 制御（送信フロー・中止要求・保留オファー順次処理）。

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowTextW;

use zerohop::app::state::{AppStateKind, UiCommand};
use zerohop::domain::model::ThreadKey;

use super::dialogs::{confirm_file_offer_dialog, pick_open_file_dialog, pick_save_file_dialog};
use super::main_view::set_notice_text;
use super::state_helpers::{UiHandles, UiState, with_state, with_state_mut, with_ui_and_state_mut};
use super::to_wide;

pub(crate) fn sync_file_transfer_button(handles: &UiHandles, state: &UiState) {
    if handles.main_file_btn.is_null() {
        return;
    }
    let (label, enabled) = if state.active_transfer.is_some() {
        ("転送中止(&F)", state.app_state == AppStateKind::LoggedIn)
    } else {
        let can_send = state.app_state == AppStateKind::LoggedIn
            && match &state.active_thread {
                ThreadKey::Peer(pid) => {
                    state.peers.iter().any(|p| &p.peer_id == pid && p.is_online)
                }
                ThreadKey::Broadcast => false,
            };
        ("ファイル(&F)...", can_send)
    };
    let w_label = to_wide(label);
    unsafe {
        SetWindowTextW(handles.main_file_btn, w_label.as_ptr());
        EnableWindow(handles.main_file_btn, i32::from(enabled));
    }
}

pub(crate) fn handle_file_button_clicked(hwnd: HWND) {
    let is_transferring = with_state(|s| s.active_transfer.is_some()).unwrap_or(false);
    if is_transferring {
        cancel_active_file_transfer();
    } else {
        start_send_file_flow(hwnd);
    }
}

pub(crate) fn start_send_file_flow(hwnd: HWND) {
    let target_peer = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn || state.modal_open {
            return None;
        }
        if state.active_transfer.is_some() {
            set_notice_text(
                handles,
                state,
                "現在別のファイル転送が進行中です。完了または中止後に実行してください。",
            );
            return None;
        }
        match &state.active_thread {
            ThreadKey::Peer(pid) => {
                let online = state.peers.iter().any(|p| &p.peer_id == pid && p.is_online);
                if online {
                    state.modal_open = true;
                    Some(pid.clone())
                } else {
                    set_notice_text(
                        handles,
                        state,
                        "選択中の相手がオフラインのためファイル送信できません。",
                    );
                    None
                }
            }
            ThreadKey::Broadcast => {
                set_notice_text(
                    handles,
                    state,
                    "全体チャットではファイル送信できません。左の一覧から送信先の相手を選択してください。",
                );
                None
            }
        }
    })
    .flatten();

    let Some(peer_id) = target_peer else {
        return;
    };

    let selected = pick_open_file_dialog(hwnd);
    with_ui_and_state_mut(|handles, state| {
        state.modal_open = false;
        if let Some(path) = selected {
            let _ = state.cmd_tx.try_send(UiCommand::SendFile {
                peer_id,
                file_path: path,
            });
            set_notice_text(handles, state, "ファイル送信要求を送信しています...");
        }
    });
    process_pending_file_offers(hwnd);
}

pub(crate) fn cancel_active_file_transfer() {
    with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn {
            return;
        }
        if let Some(tr) = &state.active_transfer {
            let tid = tr.transfer_id.clone();
            let _ = state
                .cmd_tx
                .try_send(UiCommand::CancelFileTransfer { transfer_id: tid });
            set_notice_text(handles, state, "ファイル転送の中止を要求しました。");
        } else {
            set_notice_text(handles, state, "現在進行中のファイル転送はありません。");
        }
    });
}

pub(crate) fn process_pending_file_offers(hwnd: HWND) {
    loop {
        let next_offer = with_state_mut(|state| {
            if state.app_state != AppStateKind::LoggedIn || state.modal_open {
                return None;
            }
            let offer = state.pending_file_offers.pop_front()?;
            state.modal_open = true;
            Some(offer)
        })
        .flatten();

        let Some(offer) = next_offer else {
            break;
        };

        let accepted = confirm_file_offer_dialog(
            hwnd,
            &offer.peer_name,
            &offer.filename,
            offer.file_size,
            &offer.sha256_hex,
        );
        let save_path = if accepted {
            pick_save_file_dialog(hwnd, &offer.filename)
        } else {
            None
        };

        with_ui_and_state_mut(|handles, state| {
            state.modal_open = false;
            if state.app_state == AppStateKind::LoggedIn {
                let accept_final = save_path.is_some();
                let _ = state.cmd_tx.try_send(UiCommand::RespondFileOffer {
                    transfer_id: offer.transfer_id,
                    accept: accept_final,
                    save_path,
                });
                if accept_final {
                    set_notice_text(
                        handles,
                        state,
                        &format!("ファイル受信を開始します: {}", offer.filename),
                    );
                }
            }
        });
    }
}
