use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use tokio::sync::mpsc;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ActiveSession, Coordinator, InternalMsg, allow_anomaly_for, emit_event};
use crate::app::state::AppEvent;
use crate::crypto::replay::{
    DEFAULT_TIMESTAMP_WINDOW_SECS, ReplayCheckError, check_timestamp_window,
};
use crate::domain::model::{DeliveryState, InMemoryChatMessage, ReplyReference, ThreadKey};
use crate::domain::protocol::TcpPayload;
use crate::domain::validation::{
    contains_mention, sanitize_reply_reference, validate_and_normalize_display_name,
    validate_chat_body, validate_identifier, validate_received_chat_body,
};
use crate::network::current_unix_timestamp;
use crate::network::tcp_transport::{
    InboundTcpMessage, send_broadcast_control, send_tcp_control_frame,
};

fn reply_payload_fields(
    reply_to: Option<&ReplyReference>,
) -> (Option<String>, Option<String>, Option<String>) {
    match reply_to {
        Some(r) => (
            Some(r.message_id.clone()),
            Some(r.sender_name.clone()),
            Some(r.preview.clone()),
        ),
        None => (None, None, None),
    }
}

fn spawn_ack_reply_for(active: &mut ActiveSession, sender_id: &str, message_id: &str) {
    let Some(peer) = active.peers.get(sender_id) else {
        return;
    };
    let target_addr = SocketAddr::new(peer.ip, peer.tcp_port);
    let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
        return;
    };
    let ack = TcpPayload::Ack {
        message_id: message_id.to_string(),
        receiver_id: active.ephemeral_peer_id.clone(),
        timestamp: current_unix_timestamp(),
    };
    let cancel = active.cancel.clone();
    active.outbound_tasks.spawn(async move {
        tokio::select! {
            _ = cancel.cancelled() => {},
            _ = send_tcp_control_frame(target_addr, &msg_key, &ack) => {},
        }
    });
}

impl Coordinator {
    pub(super) fn handle_inbound_tcp(
        &mut self,
        msg: InboundTcpMessage,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        let now_unix = current_unix_timestamp();
        match &msg.payload {
            TcpPayload::Hello {
                sender_id,
                sender_name,
                tcp_port,
                status,
                timestamp,
                seq,
                advertised_ip,
            } => {
                self.handle_inbound_hello(
                    msg.peer_ip,
                    sender_id,
                    sender_name,
                    *tcp_port,
                    *status,
                    *timestamp,
                    *seq,
                    *advertised_ip,
                    now_unix,
                );
            }
            TcpPayload::Chat {
                message_id,
                sender_id,
                sender_name,
                is_broadcast,
                body,
                timestamp,
                reply_to_id,
                reply_to_sender,
                reply_to_preview,
            } => {
                let reply_ref = sanitize_reply_reference(
                    reply_to_id.as_deref(),
                    reply_to_sender.as_deref(),
                    reply_to_preview.as_deref(),
                );
                self.handle_inbound_chat(
                    msg.peer_ip,
                    message_id,
                    sender_id,
                    sender_name,
                    *is_broadcast,
                    body,
                    *timestamp,
                    reply_ref,
                    now_unix,
                );
            }
            TcpPayload::Ack {
                message_id,
                receiver_id,
                timestamp,
            } => {
                self.handle_inbound_ack(msg.peer_ip, message_id, receiver_id, *timestamp, now_unix);
            }
            TcpPayload::FileOffer {
                transfer_id,
                sender_id,
                filename,
                file_size,
                sha256_hex,
                timestamp,
            } => {
                self.handle_inbound_file_offer(
                    msg.peer_ip,
                    transfer_id,
                    sender_id,
                    filename,
                    *file_size,
                    sha256_hex,
                    *timestamp,
                    now_unix,
                );
            }
            TcpPayload::FileResponse {
                transfer_id,
                sender_id,
                accepted,
                timestamp,
            } => {
                self.handle_inbound_file_response(
                    msg.peer_ip,
                    transfer_id,
                    sender_id,
                    *accepted,
                    *timestamp,
                    now_unix,
                    internal_tx,
                );
            }
            TcpPayload::FileCancel {
                transfer_id,
                sender_id,
                timestamp,
            } => {
                self.handle_inbound_file_cancel(
                    msg.peer_ip,
                    transfer_id,
                    sender_id,
                    *timestamp,
                    now_unix,
                );
            }
            TcpPayload::DeleteMessage {
                message_id,
                sender_id,
                is_broadcast,
                timestamp,
            } => {
                self.handle_inbound_delete_message(
                    msg.peer_ip,
                    message_id,
                    sender_id,
                    *is_broadcast,
                    *timestamp,
                    now_unix,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_inbound_chat(
        &mut self,
        peer_ip: IpAddr,
        message_id: &str,
        sender_id: &str,
        sender_name: &str,
        is_broadcast: bool,
        body: &str,
        timestamp: i64,
        reply_to: Option<ReplyReference>,
        now_unix: i64,
    ) {
        let mut events = Vec::new();
        if let Some(active) = &mut self.active {
            if sender_id == active.ephemeral_peer_id
                || validate_identifier(sender_id).is_err()
                || validate_identifier(message_id).is_err()
            {
                return;
            }

            match active
                .replay
                .check_and_record(sender_id, message_id, timestamp, now_unix)
            {
                Ok(()) => {}
                Err(ReplayCheckError::ClockSkew { skew_seconds }) => {
                    if allow_anomaly_for(active, peer_ip) {
                        emit_event(
                            &self.event_tx,
                            &self.wake_ui,
                            AppEvent::ClockSkewDetected {
                                peer_ip,
                                skew_seconds,
                            },
                        );
                    }
                    return;
                }
                Err(ReplayCheckError::DuplicateMessage) => {
                    // 重複メッセージは二重保存しないが Ack のみ再送可能とする
                    spawn_ack_reply_for(active, sender_id, message_id);
                    return;
                }
            }

            let Ok(clean_body) = validate_received_chat_body(body) else {
                return;
            };
            let Ok(clean_name) = validate_and_normalize_display_name(sender_name) else {
                return;
            };

            let thread = if is_broadcast {
                ThreadKey::Broadcast
            } else {
                ThreadKey::Peer(sender_id.to_string())
            };
            let preview: String = clean_body
                .replace(['\r', '\n'], " ")
                .chars()
                .take(60)
                .collect();
            let is_mentioned = contains_mention(&clean_body, &active.display_name);
            let chat_msg = InMemoryChatMessage::new(
                message_id.to_string(),
                sender_id.to_string(),
                clean_name.clone(),
                clean_body,
                timestamp,
                DeliveryState::Received,
            )
            .with_reply_to(reply_to);

            let push_res = {
                let mut log_guard = self
                    .shared_log
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let res = log_guard.push_message(thread.clone(), chat_msg);
                let new_count = log_guard.thread_len(&thread);
                let total_bytes = log_guard.current_total_bytes();
                (res, new_count, total_bytes)
            };

            if let (Ok(_), new_count, total_log_bytes) = push_res {
                events.push(AppEvent::ThreadUpdated {
                    thread: thread.clone(),
                    new_count,
                    total_log_bytes,
                });
                events.push(AppEvent::IncomingMessageReceived {
                    thread,
                    sender_name: clean_name,
                    preview,
                    is_mentioned,
                });
                spawn_ack_reply_for(active, sender_id, message_id);
            }
        }
        for ev in events {
            self.emit(ev);
        }
    }

    fn handle_inbound_ack(
        &mut self,
        peer_ip: IpAddr,
        message_id: &str,
        receiver_id: &str,
        timestamp: i64,
        now_unix: i64,
    ) {
        if let Err(skew_seconds) =
            check_timestamp_window(timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
        {
            if self.allow_anomaly_now(peer_ip) {
                self.emit(AppEvent::ClockSkewDetected {
                    peer_ip,
                    skew_seconds,
                });
            }
            return;
        }
        if validate_identifier(message_id).is_err() || validate_identifier(receiver_id).is_err() {
            return;
        }

        let updated_thread = {
            let mut log_guard = self
                .shared_log
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let peer_thread = ThreadKey::Peer(receiver_id.to_string());
            if log_guard.update_delivery_ack(&peer_thread, message_id, receiver_id) {
                Some(peer_thread)
            } else if log_guard.update_delivery_ack(&ThreadKey::Broadcast, message_id, receiver_id)
            {
                Some(ThreadKey::Broadcast)
            } else {
                None
            }
        };

        if let Some(thread) = updated_thread {
            self.emit(AppEvent::DeliveryUpdated {
                thread,
                message_id: message_id.to_string(),
            });
        }
    }

    fn handle_inbound_delete_message(
        &mut self,
        peer_ip: IpAddr,
        message_id: &str,
        sender_id: &str,
        is_broadcast: bool,
        timestamp: i64,
        now_unix: i64,
    ) {
        let mut updated: Option<(ThreadKey, usize, usize)> = None;
        let mut skew_event: Option<AppEvent> = None;

        if let Some(active) = &mut self.active {
            if sender_id == active.ephemeral_peer_id
                || validate_identifier(sender_id).is_err()
                || validate_identifier(message_id).is_err()
            {
                return;
            }

            let replay_key = format!("del:{message_id}");
            match active
                .replay
                .check_and_record(sender_id, &replay_key, timestamp, now_unix)
            {
                Ok(()) => {}
                Err(ReplayCheckError::ClockSkew { skew_seconds }) => {
                    if allow_anomaly_for(active, peer_ip) {
                        skew_event = Some(AppEvent::ClockSkewDetected {
                            peer_ip,
                            skew_seconds,
                        });
                    }
                }
                Err(ReplayCheckError::DuplicateMessage) => return,
            }

            if skew_event.is_none() {
                let thread = if is_broadcast {
                    ThreadKey::Broadcast
                } else {
                    ThreadKey::Peer(sender_id.to_string())
                };
                let mut log_guard = self
                    .shared_log
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if log_guard.mark_message_deleted(&thread, message_id, sender_id) {
                    let new_count = log_guard.thread_len(&thread);
                    let total_log_bytes = log_guard.current_total_bytes();
                    updated = Some((thread, new_count, total_log_bytes));
                }
            }
        }

        if let Some(ev) = skew_event {
            self.emit(ev);
        }
        if let Some((thread, new_count, total_log_bytes)) = updated {
            self.emit(AppEvent::ThreadUpdated {
                thread,
                new_count,
                total_log_bytes,
            });
        }
    }

    pub(super) fn handle_delete_message(&mut self, thread: ThreadKey, message_id: String) {
        let Some(active) = &mut self.active else {
            return;
        };
        let my_id = active.ephemeral_peer_id.clone();
        let updated = {
            let mut log_guard = self
                .shared_log
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if log_guard.mark_message_deleted(&thread, &message_id, &my_id) {
                Some((
                    log_guard.thread_len(&thread),
                    log_guard.current_total_bytes(),
                ))
            } else {
                None
            }
        };
        let Some((new_count, total_log_bytes)) = updated else {
            return;
        };

        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };
        let now_unix = current_unix_timestamp();
        let is_broadcast = matches!(thread, ThreadKey::Broadcast);
        let payload = TcpPayload::DeleteMessage {
            message_id,
            sender_id: my_id,
            is_broadcast,
            timestamp: now_unix,
        };
        let cancel = active.cancel.clone();

        match &thread {
            ThreadKey::Peer(peer_id) => {
                if let Some(peer) = active.peers.get(peer_id) {
                    let target_addr = SocketAddr::new(peer.ip, peer.tcp_port);
                    active.outbound_tasks.spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => {},
                            _ = send_tcp_control_frame(target_addr, &msg_key, &payload) => {},
                        }
                    });
                }
            }
            ThreadKey::Broadcast => {
                let targets: Vec<(String, SocketAddr)> = active
                    .peers
                    .list_views()
                    .into_iter()
                    .filter(|v| v.is_online)
                    .filter_map(|v| {
                        let p = active.peers.get(&v.peer_id)?;
                        Some((p.peer_id.clone(), SocketAddr::new(p.ip, p.tcp_port)))
                    })
                    .collect();
                if !targets.is_empty() {
                    active.outbound_tasks.spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => {},
                            _ = send_broadcast_control(targets, msg_key, payload) => {},
                        }
                    });
                }
            }
        }

        self.emit(AppEvent::ThreadUpdated {
            thread,
            new_count,
            total_log_bytes,
        });
    }

    pub(super) fn handle_send_chat(
        &mut self,
        thread: ThreadKey,
        raw_body: Zeroizing<String>,
        reply_to: Option<ReplyReference>,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        let body = match validate_chat_body(&raw_body) {
            Ok(b) => Zeroizing::new(b),
            Err(err) => {
                self.emit(AppEvent::ErrorNotice(err.to_string()));
                return;
            }
        };

        let Some(active) = &mut self.active else {
            return;
        };
        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };

        let message_id = Uuid::new_v4().to_string();
        let now_unix = current_unix_timestamp();

        match &thread {
            ThreadKey::Peer(peer_id) => {
                let Some(peer) = active.peers.get(peer_id) else {
                    emit_event(
                        &self.event_tx,
                        &self.wake_ui,
                        AppEvent::ErrorNotice("指定した送信先ピアが見つかりません".to_string()),
                    );
                    return;
                };
                let target_addr = SocketAddr::new(peer.ip, peer.tcp_port);
                let msg = InMemoryChatMessage::new(
                    message_id.clone(),
                    active.ephemeral_peer_id.clone(),
                    active.display_name.clone(),
                    (*body).clone(),
                    now_unix,
                    DeliveryState::DirectSending,
                )
                .with_reply_to(reply_to.clone());
                let (new_count, total_log_bytes) = {
                    let mut log_guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Err(err) = log_guard.push_message(thread.clone(), msg) {
                        emit_event(
                            &self.event_tx,
                            &self.wake_ui,
                            AppEvent::ErrorNotice(err.to_string()),
                        );
                        return;
                    }
                    (
                        log_guard.thread_len(&thread),
                        log_guard.current_total_bytes(),
                    )
                };
                emit_event(
                    &self.event_tx,
                    &self.wake_ui,
                    AppEvent::ThreadUpdated {
                        thread: thread.clone(),
                        new_count,
                        total_log_bytes,
                    },
                );

                let (reply_to_id, reply_to_sender, reply_to_preview) =
                    reply_payload_fields(reply_to.as_ref());
                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: false,
                    body: (*body).clone(),
                    timestamp: now_unix,
                    reply_to_id,
                    reply_to_sender,
                    reply_to_preview,
                };
                let tx = internal_tx.clone();
                let cancel = active.cancel.clone();
                active.outbound_tasks.spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        res = send_tcp_control_frame(target_addr, &msg_key, &payload) => {
                            let _ = tx.send(InternalMsg::DirectSendFinished {
                                thread,
                                message_id,
                                result: res.map_err(|e| e.to_string()),
                            }).await;
                        }
                    }
                });
            }
            ThreadKey::Broadcast => {
                let targets: Vec<(String, SocketAddr)> = active
                    .peers
                    .list_views()
                    .into_iter()
                    .filter(|v| v.is_online)
                    .filter_map(|v| {
                        let p = active.peers.get(&v.peer_id)?;
                        Some((p.peer_id.clone(), SocketAddr::new(p.ip, p.tcp_port)))
                    })
                    .collect();

                let msg = InMemoryChatMessage::new(
                    message_id.clone(),
                    active.ephemeral_peer_id.clone(),
                    active.display_name.clone(),
                    (*body).clone(),
                    now_unix,
                    DeliveryState::new_broadcast(targets.len()),
                )
                .with_reply_to(reply_to.clone());
                let (new_count, total_log_bytes) = {
                    let mut log_guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Err(err) = log_guard.push_message(thread.clone(), msg) {
                        emit_event(
                            &self.event_tx,
                            &self.wake_ui,
                            AppEvent::ErrorNotice(err.to_string()),
                        );
                        return;
                    }
                    (
                        log_guard.thread_len(&thread),
                        log_guard.current_total_bytes(),
                    )
                };
                emit_event(
                    &self.event_tx,
                    &self.wake_ui,
                    AppEvent::ThreadUpdated {
                        thread: thread.clone(),
                        new_count,
                        total_log_bytes,
                    },
                );

                if targets.is_empty() {
                    return;
                }

                let (reply_to_id, reply_to_sender, reply_to_preview) =
                    reply_payload_fields(reply_to.as_ref());
                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: true,
                    body: (*body).clone(),
                    timestamp: now_unix,
                    reply_to_id,
                    reply_to_sender,
                    reply_to_preview,
                };
                let tx = internal_tx.clone();
                let cancel = active.cancel.clone();
                active.outbound_tasks.spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        results = send_broadcast_control(targets, msg_key, payload) => {
                            let failures = results
                                .into_iter()
                                .filter_map(|(pid, r)| r.err().map(|e| (pid, e.to_string())))
                                .collect();
                            let _ = tx.send(InternalMsg::BroadcastSendFinished {
                                thread,
                                message_id,
                                failures,
                            }).await;
                        }
                    }
                });
            }
        }
    }

    pub(super) fn handle_retry_chat(
        &mut self,
        thread: ThreadKey,
        message_id: String,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        let Some(active) = &mut self.active else {
            return;
        };
        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };

        let found = {
            let log_guard = self
                .shared_log
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let len = log_guard.thread_len(&thread);
            (0..len).rev().find_map(|idx| {
                let m = log_guard.get_message(&thread, idx)?;
                if m.message_id == message_id {
                    Some((
                        m.body.clone(),
                        m.timestamp,
                        m.delivery.clone(),
                        m.reply_to.clone(),
                    ))
                } else {
                    None
                }
            })
        };

        let Some((body, timestamp, delivery, reply_to)) = found else {
            return;
        };

        match (&thread, delivery) {
            (
                ThreadKey::Peer(peer_id),
                DeliveryState::DirectFailed | DeliveryState::DirectSending,
            ) => {
                let Some(peer) = active.peers.get(peer_id) else {
                    emit_event(
                        &self.event_tx,
                        &self.wake_ui,
                        AppEvent::ErrorNotice("再送先のピアが見つかりません".to_string()),
                    );
                    return;
                };
                let target_addr = SocketAddr::new(peer.ip, peer.tcp_port);
                let (reply_to_id, reply_to_sender, reply_to_preview) =
                    reply_payload_fields(reply_to.as_ref());
                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: false,
                    body,
                    timestamp,
                    reply_to_id,
                    reply_to_sender,
                    reply_to_preview,
                };
                let tx = internal_tx.clone();
                let cancel = active.cancel.clone();
                active.outbound_tasks.spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        res = send_tcp_control_frame(target_addr, &msg_key, &payload) => {
                            let _ = tx.send(InternalMsg::DirectSendFinished {
                                thread,
                                message_id,
                                result: res.map_err(|e| e.to_string()),
                            }).await;
                        }
                    }
                });
            }
            (
                ThreadKey::Broadcast,
                DeliveryState::Broadcast {
                    acked_peers,
                    failed_peers,
                    ..
                },
            ) => {
                let mut target_map: HashMap<String, SocketAddr> = HashMap::new();
                for v in active.peers.list_views() {
                    if !acked_peers.contains(&v.peer_id)
                        && (v.is_online || failed_peers.contains(&v.peer_id))
                        && let Some(p) = active.peers.get(&v.peer_id)
                    {
                        target_map.insert(p.peer_id.clone(), SocketAddr::new(p.ip, p.tcp_port));
                    }
                }
                let targets: Vec<(String, SocketAddr)> = target_map.into_iter().collect();
                if targets.is_empty() {
                    return;
                }

                let (reply_to_id, reply_to_sender, reply_to_preview) =
                    reply_payload_fields(reply_to.as_ref());
                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: true,
                    body,
                    timestamp,
                    reply_to_id,
                    reply_to_sender,
                    reply_to_preview,
                };
                let tx = internal_tx.clone();
                let cancel = active.cancel.clone();
                active.outbound_tasks.spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {},
                        results = send_broadcast_control(targets, msg_key, payload) => {
                            let failures = results
                                .into_iter()
                                .filter_map(|(pid, r)| r.err().map(|e| (pid, e.to_string())))
                                .collect();
                            let _ = tx.send(InternalMsg::BroadcastSendFinished {
                                thread,
                                message_id,
                                failures,
                            }).await;
                        }
                    }
                });
            }
            _ => {}
        }
    }

    pub(super) fn handle_clear_session_chat(&self, thread: Option<ThreadKey>) {
        if self.active.is_none() {
            return;
        }
        match thread {
            Some(key) => {
                let (new_count, total_log_bytes) = {
                    let mut guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let _ = guard.clear_thread(&key);
                    (guard.thread_len(&key), guard.current_total_bytes())
                };
                self.emit(AppEvent::ThreadUpdated {
                    thread: key,
                    new_count,
                    total_log_bytes,
                });
            }
            None => {
                let total_log_bytes = {
                    let mut guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let _ = guard.clear_all();
                    guard.current_total_bytes()
                };
                self.emit(AppEvent::ThreadUpdated {
                    thread: ThreadKey::Broadcast,
                    new_count: 0,
                    total_log_bytes,
                });
            }
        }
    }
}
