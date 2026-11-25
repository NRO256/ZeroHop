use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ActiveSession, Coordinator, InternalMsg, emit_event};
use crate::app::state::{AppEvent, AppStateKind};
use crate::crypto::replay::{
    DEFAULT_TIMESTAMP_WINDOW_SECS, ReplayCheckError, check_timestamp_window,
};
use crate::domain::model::{DeliveryState, InMemoryChatMessage, ThreadKey};
use crate::domain::protocol::TcpPayload;
use crate::domain::validation::{
    sanitize_filename, validate_file_size, validate_identifier, validate_sha256_hex,
};
use crate::network::current_unix_timestamp;
use crate::network::tcp_transport::{
    InboundTcpFileChunk, send_file_chunks_stream, send_tcp_control_frame,
};
use crate::storage::transfer_store::{EncryptedTransferTempFile, compute_file_sha256_streaming};

const MAX_PENDING_FILE_OFFERS: usize = 16;

pub(super) struct OutboundTransferState {
    pub peer_id: String,
    pub peer_addr: SocketAddr,
    pub filename: String,
    pub file_path: PathBuf,
    pub file_size: u64,
    pub accepted: bool,
    pub cancel_token: CancellationToken,
}

pub(super) struct PendingInboundOffer {
    pub peer_id: String,
    pub peer_addr: SocketAddr,
    pub filename: String,
    pub file_size: u64,
    pub sha256_hex: String,
}

pub(super) struct ActiveInboundTransfer {
    pub peer_id: String,
    pub peer_addr: SocketAddr,
    pub filename: String,
    pub expected_size: u64,
    pub expected_sha256_hex: String,
    pub save_path: PathBuf,
    pub temp_file: EncryptedTransferTempFile,
    pub last_reported_bytes: u64,
}

fn spawn_file_response_async(
    active: &mut ActiveSession,
    peer_addr: SocketAddr,
    transfer_id: String,
    accepted: bool,
) {
    let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
        return;
    };
    let response = TcpPayload::FileResponse {
        transfer_id,
        sender_id: active.ephemeral_peer_id.clone(),
        accepted,
        timestamp: current_unix_timestamp(),
    };
    active.outbound_tasks.spawn(async move {
        let _ = send_tcp_control_frame(peer_addr, &msg_key, &response).await;
    });
}

fn spawn_file_cancel_async(active: &mut ActiveSession, peer_addr: SocketAddr, transfer_id: String) {
    let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
        return;
    };
    let cancel_msg = TcpPayload::FileCancel {
        transfer_id,
        sender_id: active.ephemeral_peer_id.clone(),
        timestamp: current_unix_timestamp(),
    };
    active.outbound_tasks.spawn(async move {
        let _ = send_tcp_control_frame(peer_addr, &msg_key, &cancel_msg).await;
    });
}

impl Coordinator {
    fn append_transfer_system_note(&self, peer_id: &str, body: String) {
        let Some(active) = &self.active else {
            return;
        };
        let thread = ThreadKey::Peer(peer_id.to_string());
        let msg = InMemoryChatMessage::new(
            Uuid::new_v4().to_string(),
            active.ephemeral_peer_id.clone(),
            "システム",
            body,
            current_unix_timestamp(),
            DeliveryState::Received,
        );
        let new_count = {
            let mut guard = self
                .shared_log
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.push_message(thread.clone(), msg).is_ok() {
                Some(guard.thread_len(&thread))
            } else {
                None
            }
        };
        if let Some(count) = new_count {
            self.emit(AppEvent::ThreadUpdated {
                thread,
                new_count: count,
                total_log_bytes: self.current_log_bytes(),
            });
        }
    }

    pub(super) fn handle_send_file(
        &mut self,
        peer_id: String,
        file_path: PathBuf,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        let sanitized_name = match file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(crate::domain::validation::ValidationError::InvalidFilename)
            .and_then(sanitize_filename)
        {
            Ok(name) => name,
            Err(err) => {
                self.emit(AppEvent::ErrorNotice(err.to_string()));
                return;
            }
        };

        let (file_size, sha256_hex) = match compute_file_sha256_streaming(&file_path) {
            Ok(res) => res,
            Err(err) => {
                self.emit(AppEvent::ErrorNotice(err.to_string()));
                return;
            }
        };

        let Some(active) = &mut self.active else {
            return;
        };
        let Some(peer) = active.peers.get(&peer_id).filter(|p| p.is_online) else {
            self.emit(AppEvent::ErrorNotice(
                "相手がオフラインまたは見つからないためファイルを送信できません".to_string(),
            ));
            return;
        };
        let peer_addr = SocketAddr::new(peer.ip, peer.tcp_port);
        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };

        let transfer_id = Uuid::new_v4().to_string();
        let cancel_token = active.cancel.child_token();
        active.outbound_transfers.insert(
            transfer_id.clone(),
            OutboundTransferState {
                peer_id: peer_id.clone(),
                peer_addr,
                filename: sanitized_name.clone(),
                file_path,
                file_size,
                accepted: false,
                cancel_token,
            },
        );

        let payload = TcpPayload::FileOffer {
            transfer_id: transfer_id.clone(),
            sender_id: active.ephemeral_peer_id.clone(),
            filename: sanitized_name,
            file_size,
            sha256_hex,
            timestamp: current_unix_timestamp(),
        };
        let tx = internal_tx.clone();
        active.outbound_tasks.spawn(async move {
            let res = send_tcp_control_frame(peer_addr, &msg_key, &payload)
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(InternalMsg::FileOfferSendFinished {
                    transfer_id,
                    result: res,
                })
                .await;
        });
    }

    pub(super) fn handle_respond_file_offer(
        &mut self,
        transfer_id: String,
        accept: bool,
        save_path: Option<PathBuf>,
    ) {
        let Some(active) = &mut self.active else {
            return;
        };
        let Some(offer) = active.pending_inbound_offers.remove(&transfer_id) else {
            return;
        };

        let mut accepted = false;
        let mut create_err: Option<String> = None;
        if accept && let Some(dest_path) = save_path {
            match EncryptedTransferTempFile::create(&self.options.paths, &transfer_id) {
                Ok(temp_file) => {
                    active.active_inbound_transfers.insert(
                        transfer_id.clone(),
                        ActiveInboundTransfer {
                            peer_id: offer.peer_id.clone(),
                            peer_addr: offer.peer_addr,
                            filename: offer.filename.clone(),
                            expected_size: offer.file_size,
                            expected_sha256_hex: offer.sha256_hex.clone(),
                            save_path: dest_path,
                            temp_file,
                            last_reported_bytes: 0,
                        },
                    );
                    accepted = true;
                }
                Err(err) => {
                    create_err = Some(format!("暗号化一時ファイルの作成に失敗しました: {err}"));
                }
            }
        }
        if let Some(msg) = create_err {
            emit_event(&self.event_tx, &self.wake_ui, AppEvent::ErrorNotice(msg));
        }

        spawn_file_response_async(active, offer.peer_addr, transfer_id.clone(), accepted);

        if !accepted {
            self.emit(AppEvent::FileTransferFinished {
                transfer_id,
                peer_id: offer.peer_id,
                filename: offer.filename,
                is_sending: false,
                ok: false,
                message: "ファイルの受信を拒否しました".to_string(),
            });
        } else {
            self.emit(AppEvent::FileTransferProgress {
                transfer_id,
                peer_id: offer.peer_id,
                filename: offer.filename,
                is_sending: false,
                transferred_bytes: 0,
                total_bytes: offer.file_size,
            });
        }
    }

    pub(super) fn handle_cancel_file_transfer(&mut self, transfer_id: &str) {
        let Some(active) = &mut self.active else {
            return;
        };
        if let Some(tr) = active.outbound_transfers.remove(transfer_id) {
            tr.cancel_token.cancel();
            spawn_file_cancel_async(active, tr.peer_addr, transfer_id.to_string());
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id: tr.peer_id,
                filename: tr.filename,
                is_sending: true,
                ok: false,
                message: "ファイル送信を中止しました".to_string(),
            });
            return;
        }
        if let Some(tr) = active.active_inbound_transfers.remove(transfer_id) {
            let peer_id = tr.peer_id.clone();
            let peer_addr = tr.peer_addr;
            let filename = tr.filename.clone();
            drop(tr);
            spawn_file_cancel_async(active, peer_addr, transfer_id.to_string());
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id,
                filename,
                is_sending: false,
                ok: false,
                message: "ファイル受信を中止しました".to_string(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_inbound_file_offer(
        &mut self,
        peer_ip: IpAddr,
        transfer_id: &str,
        sender_id: &str,
        filename: &str,
        file_size: u64,
        sha256_hex: &str,
        timestamp: i64,
        now_unix: i64,
    ) {
        let Ok(clean_filename) = sanitize_filename(filename) else {
            return;
        };
        let Ok(clean_sha256) = validate_sha256_hex(sha256_hex) else {
            return;
        };
        if validate_identifier(transfer_id).is_err()
            || validate_identifier(sender_id).is_err()
            || validate_file_size(file_size).is_err()
        {
            return;
        }

        let Some(active) = &mut self.active else {
            return;
        };
        if sender_id == active.ephemeral_peer_id {
            return;
        }
        match active
            .replay
            .check_and_record(sender_id, transfer_id, timestamp, now_unix)
        {
            Ok(()) => {}
            Err(ReplayCheckError::ClockSkew { skew_seconds }) => {
                if super::allow_anomaly_for(active, peer_ip) {
                    self.emit(AppEvent::ClockSkewDetected {
                        peer_ip,
                        skew_seconds,
                    });
                }
                return;
            }
            Err(ReplayCheckError::DuplicateMessage) => return,
        }

        let Some(peer) = active.peers.get(sender_id).cloned() else {
            return;
        };
        let peer_addr = SocketAddr::new(peer.ip, peer.tcp_port);

        // 画面ロック中等または未承諾オファー上限超過時は自動拒否してUIモーダルを出さない
        if self.state != AppStateKind::LoggedIn
            || active.pending_inbound_offers.len() >= MAX_PENDING_FILE_OFFERS
        {
            spawn_file_response_async(active, peer_addr, transfer_id.to_string(), false);
            return;
        }

        active.pending_inbound_offers.insert(
            transfer_id.to_string(),
            PendingInboundOffer {
                peer_id: peer.peer_id.clone(),
                peer_addr,
                filename: clean_filename.clone(),
                file_size,
                sha256_hex: clean_sha256.clone(),
            },
        );

        self.emit(AppEvent::FileOfferReceived {
            transfer_id: transfer_id.to_string(),
            peer_id: peer.peer_id.clone(),
            peer_name: peer.display_name.clone(),
            filename: clean_filename,
            file_size,
            sha256_hex: clean_sha256,
        });
    }

    pub(super) fn handle_inbound_file_cancel(
        &mut self,
        peer_ip: IpAddr,
        transfer_id: &str,
        sender_id: &str,
        timestamp: i64,
        now_unix: i64,
    ) {
        if validate_identifier(transfer_id).is_err() || validate_identifier(sender_id).is_err() {
            return;
        }
        let Some(active) = &mut self.active else {
            return;
        };
        if let Err(skew_seconds) =
            check_timestamp_window(timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
        {
            if super::allow_anomaly_for(active, peer_ip) {
                self.emit(AppEvent::ClockSkewDetected {
                    peer_ip,
                    skew_seconds,
                });
            }
            return;
        }

        if let Some(tr) = active.outbound_transfers.get(transfer_id)
            && tr.peer_id == sender_id
            && let Some(removed) = active.outbound_transfers.remove(transfer_id)
        {
            removed.cancel_token.cancel();
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id: removed.peer_id,
                filename: removed.filename,
                is_sending: true,
                ok: false,
                message: "相手側によりファイル転送が中止されました".to_string(),
            });
            return;
        }

        if let Some(tr) = active.active_inbound_transfers.get(transfer_id)
            && tr.peer_id == sender_id
            && let Some(removed) = active.active_inbound_transfers.remove(transfer_id)
        {
            let peer_id = removed.peer_id.clone();
            let filename = removed.filename.clone();
            drop(removed);
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id,
                filename,
                is_sending: false,
                ok: false,
                message: "送信側によりファイル転送が中止されました".to_string(),
            });
            return;
        }

        if let Some(offer) = active.pending_inbound_offers.get(transfer_id)
            && offer.peer_id == sender_id
            && let Some(removed) = active.pending_inbound_offers.remove(transfer_id)
        {
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id: removed.peer_id,
                filename: removed.filename,
                is_sending: false,
                ok: false,
                message: "送信側によりファイル送信要求が取り消されました".to_string(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_inbound_file_response(
        &mut self,
        peer_ip: IpAddr,
        transfer_id: &str,
        sender_id: &str,
        accepted: bool,
        timestamp: i64,
        now_unix: i64,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        if validate_identifier(transfer_id).is_err() || validate_identifier(sender_id).is_err() {
            return;
        }
        let Some(active) = &mut self.active else {
            return;
        };
        if let Err(skew_seconds) =
            check_timestamp_window(timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
        {
            if super::allow_anomaly_for(active, peer_ip) {
                self.emit(AppEvent::ClockSkewDetected {
                    peer_ip,
                    skew_seconds,
                });
            }
            return;
        }

        let Some(tr) = active.outbound_transfers.get_mut(transfer_id) else {
            return;
        };
        if tr.peer_id != sender_id || tr.accepted {
            return;
        }

        if !accepted {
            let removed = active.outbound_transfers.remove(transfer_id);
            if let Some(r) = removed {
                self.emit(AppEvent::FileTransferFinished {
                    transfer_id: transfer_id.to_string(),
                    peer_id: r.peer_id,
                    filename: r.filename,
                    is_sending: true,
                    ok: false,
                    message: "相手が受信を拒否しました".to_string(),
                });
            }
            return;
        }

        tr.accepted = true;
        let peer_id = tr.peer_id.clone();
        let peer_addr = tr.peer_addr;
        let filename = tr.filename.clone();
        let file_path = tr.file_path.clone();
        let file_size = tr.file_size;
        let cancel_token = tr.cancel_token.clone();
        let my_id = active.ephemeral_peer_id.clone();
        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };
        let init_tid = transfer_id.to_string();

        let (prog_tx, mut prog_rx) = mpsc::channel::<u64>(16);
        let tx_prog = internal_tx.clone();
        let tid_prog = transfer_id.to_string();
        active.outbound_tasks.spawn(async move {
            let mut last_sent = 0u64;
            while let Some(bytes) = prog_rx.recv().await {
                if bytes.saturating_sub(last_sent) >= 256 * 1024 || bytes == file_size {
                    last_sent = bytes;
                    let _ = tx_prog
                        .send(InternalMsg::FileStreamProgress {
                            transfer_id: tid_prog.clone(),
                            transferred_bytes: bytes,
                        })
                        .await;
                }
            }
        });

        let tx_done = internal_tx.clone();
        let tid_done = transfer_id.to_string();
        active.outbound_tasks.spawn(async move {
            let res = send_file_chunks_stream(
                peer_addr,
                msg_key,
                tid_done.clone(),
                my_id,
                file_path,
                file_size,
                cancel_token,
                prog_tx,
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx_done
                .send(InternalMsg::FileStreamSendFinished {
                    transfer_id: tid_done,
                    result: res,
                })
                .await;
        });

        self.emit(AppEvent::FileTransferProgress {
            transfer_id: init_tid,
            peer_id,
            filename,
            is_sending: true,
            transferred_bytes: 0,
            total_bytes: file_size,
        });
    }

    pub(super) fn handle_inbound_file_chunk(&mut self, chunk: InboundTcpFileChunk) {
        let transfer_id = chunk.header.transfer_id.clone();
        let (temp_disk_key, finished_result) = {
            let Some(active) = &mut self.active else {
                return;
            };
            let Ok(temp_disk_key) = active.keys.with_temp_disk_key(|k| Zeroizing::new(*k)) else {
                return;
            };
            let Some(tr) = active.active_inbound_transfers.get_mut(&transfer_id) else {
                return;
            };
            if tr.peer_id != chunk.header.sender_id {
                return;
            }
            if tr
                .temp_file
                .total_plain_bytes()
                .saturating_add(chunk.data.len() as u64)
                > tr.expected_size
            {
                let removed = active.active_inbound_transfers.remove(&transfer_id);
                if let Some(r) = removed {
                    self.emit(AppEvent::FileTransferFinished {
                        transfer_id,
                        peer_id: r.peer_id,
                        filename: r.filename,
                        is_sending: false,
                        ok: false,
                        message: "受信データが宣言サイズを超過したため中断しました".to_string(),
                    });
                }
                return;
            }
            if let Err(err) = tr.temp_file.append_encrypted_chunk(
                &temp_disk_key,
                chunk.header.chunk_index,
                &chunk.data,
            ) {
                let removed = active.active_inbound_transfers.remove(&transfer_id);
                if let Some(r) = removed {
                    let msg = format!("ファイル受信中にエラーが発生しました: {err}");
                    self.emit(AppEvent::FileTransferFinished {
                        transfer_id,
                        peer_id: r.peer_id,
                        filename: r.filename,
                        is_sending: false,
                        ok: false,
                        message: msg,
                    });
                }
                return;
            }

            let cur = tr.temp_file.total_plain_bytes();
            let total = tr.expected_size;
            if cur >= total {
                (
                    Some(temp_disk_key),
                    active.active_inbound_transfers.remove(&transfer_id),
                )
            } else {
                if cur.saturating_sub(tr.last_reported_bytes) >= 256 * 1024 {
                    tr.last_reported_bytes = cur;
                    let ev = AppEvent::FileTransferProgress {
                        transfer_id: transfer_id.clone(),
                        peer_id: tr.peer_id.clone(),
                        filename: tr.filename.clone(),
                        is_sending: false,
                        transferred_bytes: cur,
                        total_bytes: total,
                    };
                    self.emit(ev);
                }
                (None, None)
            }
        };

        if let (Some(key), Some(tr)) = (temp_disk_key, finished_result) {
            let peer_id = tr.peer_id;
            let filename = tr.filename;
            let expected_size = tr.expected_size;
            let save_path = tr.save_path;
            match tr.temp_file.finalize_and_verify(
                &key,
                &save_path,
                expected_size,
                &tr.expected_sha256_hex,
            ) {
                Ok(()) => {
                    self.append_transfer_system_note(
                        &peer_id,
                        format!("[ファイル受信完了] {filename} ({expected_size} B)"),
                    );
                    self.emit(AppEvent::FileTransferFinished {
                        transfer_id,
                        peer_id,
                        filename,
                        is_sending: false,
                        ok: true,
                        message: "ファイルを受信・検証して保存しました".to_string(),
                    });
                }
                Err(err) => {
                    self.emit(AppEvent::FileTransferFinished {
                        transfer_id,
                        peer_id,
                        filename,
                        is_sending: false,
                        ok: false,
                        message: format!("ファイル検証に失敗しました: {err}"),
                    });
                }
            }
        }
    }

    pub(super) fn handle_inbound_file_stream_closed(&mut self, transfer_id: &str) {
        let removed = if let Some(active) = &mut self.active {
            active.active_inbound_transfers.remove(transfer_id)
        } else {
            None
        };
        if let Some(tr) = removed {
            let peer_id = tr.peer_id.clone();
            let filename = tr.filename.clone();
            drop(tr);
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id,
                filename,
                is_sending: false,
                ok: false,
                message: "送信側によりファイル転送が中断されました".to_string(),
            });
        }
    }

    pub(super) fn finish_outbound_transfer_with_error(
        &mut self,
        transfer_id: &str,
        message: String,
    ) {
        let removed = if let Some(active) = &mut self.active {
            active.outbound_transfers.remove(transfer_id)
        } else {
            None
        };
        if let Some(tr) = removed {
            self.emit(AppEvent::FileTransferFinished {
                transfer_id: transfer_id.to_string(),
                peer_id: tr.peer_id,
                filename: tr.filename,
                is_sending: true,
                ok: false,
                message,
            });
        }
    }

    pub(super) fn handle_file_stream_send_finished(
        &mut self,
        transfer_id: &str,
        result: Result<(), String>,
    ) {
        let removed = if let Some(active) = &mut self.active {
            active.outbound_transfers.remove(transfer_id)
        } else {
            None
        };
        let Some(tr) = removed else {
            return;
        };
        match result {
            Ok(()) => {
                self.append_transfer_system_note(
                    &tr.peer_id,
                    format!("[ファイル送信完了] {} ({} B)", tr.filename, tr.file_size),
                );
                self.emit(AppEvent::FileTransferFinished {
                    transfer_id: transfer_id.to_string(),
                    peer_id: tr.peer_id,
                    filename: tr.filename,
                    is_sending: true,
                    ok: true,
                    message: "ファイル送信が完了しました".to_string(),
                });
            }
            Err(reason) => {
                self.emit(AppEvent::FileTransferFinished {
                    transfer_id: transfer_id.to_string(),
                    peer_id: tr.peer_id,
                    filename: tr.filename,
                    is_sending: true,
                    ok: false,
                    message: format!("ファイル送信に失敗しました: {reason}"),
                });
            }
        }
    }
}
