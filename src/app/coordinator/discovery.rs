use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use super::{Coordinator, HELLO_REPLY_COOLDOWN, InternalMsg, PEER_SEQ_TTL_SECS, emit_event};
use crate::app::state::AppEvent;
use crate::crypto::replay::{DEFAULT_TIMESTAMP_WINDOW_SECS, check_timestamp_window};
use crate::domain::model::{PeerInfo, PeerOrigin, ThreadKey, UserStatus};
use crate::domain::protocol::TcpPayload;
use crate::domain::validation::{
    validate_and_normalize_display_name, validate_identifier, validate_manual_peer_endpoint,
    validate_port,
};
use crate::network::current_unix_timestamp;
use crate::network::nic::resolve_active_nic_from_str;
use crate::network::tcp_transport::send_tcp_control_frame;
use crate::network::udp_discovery::{
    UdpProcessOutcome, normalize_ip, process_udp_datagram, send_encrypted_beacon,
};

const MAX_PEER_SEQ_TRACKED: usize = 512;

pub(super) struct PeerSeqTracker {
    entries: HashMap<String, (u64, i64)>,
}

impl PeerSeqTracker {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub(super) fn check_and_record(&mut self, peer_id: &str, seq: u64, now_unix: i64) -> bool {
        if seq == 0 {
            return false;
        }
        if let Some(&(last_seq, _)) = self.entries.get(peer_id)
            && seq <= last_seq
        {
            return false;
        }
        if !self.entries.contains_key(peer_id) && self.entries.len() >= MAX_PEER_SEQ_TRACKED {
            let mut removed_keys = Vec::new();
            for (k, &(_, ts)) in &self.entries {
                if now_unix.saturating_sub(ts).abs() > PEER_SEQ_TTL_SECS {
                    removed_keys.push(k.clone());
                }
            }
            for mut k in removed_keys {
                self.entries.remove(&k);
                k.zeroize();
            }
            if self.entries.len() >= MAX_PEER_SEQ_TRACKED
                && let Some(mut oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
                oldest_key.zeroize();
            }
        }
        self.entries.insert(peer_id.to_string(), (seq, now_unix));
        true
    }

    pub(super) fn clear(&mut self) {
        for (mut key, _) in self.entries.drain() {
            key.zeroize();
        }
    }
}

impl Drop for PeerSeqTracker {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Coordinator {
    pub(super) fn send_single_beacon_async(&mut self) {
        let Some(active) = &mut self.active else {
            return;
        };
        let Some(target) = active.udp_target else {
            return;
        };
        let Ok(beacon_key) = active.keys.with_beacon_key(|k| Zeroizing::new(*k)) else {
            return;
        };
        let seq = active.next_udp_seq();
        let advertised_ip = active.advertised_ip_for_target(Some(target.ip()));
        let sock = std::sync::Arc::clone(&active.udp_socket);
        let payload = crate::domain::protocol::UdpPayload::Beacon {
            peer_id: active.ephemeral_peer_id.clone(),
            display_name: active.display_name.clone(),
            tcp_port: active.tcp_port,
            status: active.status,
            timestamp: current_unix_timestamp(),
            seq,
            advertised_ip,
        };
        let cancel = active.cancel.clone();
        active.outbound_tasks.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {},
                _ = send_encrypted_beacon(&sock, target, &beacon_key, &payload) => {},
            }
        });
    }

    pub(super) fn handle_udp_datagram(&mut self, src_addr: SocketAddr, data: &[u8]) {
        let outcome = {
            let Some(active) = &mut self.active else {
                return;
            };
            let Ok(beacon_key) = active.keys.with_beacon_key(|k| Zeroizing::new(*k)) else {
                return;
            };
            let mut anom_guard = match active.anomaly_limiter.try_lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            process_udp_datagram(
                &beacon_key,
                &active.ephemeral_peer_id,
                src_addr.ip(),
                data,
                Instant::now(),
                current_unix_timestamp(),
                &mut active.udp_ip_limiter,
                &mut anom_guard,
            )
        };

        let now_unix = current_unix_timestamp();
        match outcome {
            UdpProcessOutcome::Beacon {
                peer_ip,
                peer_id,
                display_name,
                tcp_port,
                status,
                seq,
                ..
            } => {
                let mut events = Vec::new();
                if let Some(active) = &mut self.active {
                    if !active
                        .udp_seq_tracker
                        .check_and_record(&peer_id, seq, now_unix)
                    {
                        return;
                    }
                    let was_online = active.peers.get(&peer_id).is_some_and(|p| p.is_online);
                    let existing_origin = active.peers.get(&peer_id).map(|p| p.origin);
                    let info = PeerInfo {
                        peer_id: peer_id.clone(),
                        display_name: display_name.clone(),
                        ip: peer_ip,
                        tcp_port,
                        status,
                        is_online: true,
                        origin: existing_origin.unwrap_or(PeerOrigin::Discovered),
                        last_seen_unix: now_unix,
                        unread_count: 0,
                    };
                    let res = {
                        let mut log_guard = self
                            .shared_log
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        active.peers.upsert_online_peer(info, &mut log_guard)
                    };
                    match res {
                        Ok(_) => {
                            if !was_online {
                                events.push(AppEvent::PeerJoined {
                                    peer_id,
                                    display_name,
                                });
                            }
                            events.push(AppEvent::PeerListChanged(active.peers.list_views()));
                        }
                        Err(err) => {
                            events.push(AppEvent::ErrorNotice(err.to_string()));
                        }
                    }
                }
                for ev in events {
                    self.emit(ev);
                }
            }
            UdpProcessOutcome::Bye { peer_id, seq, .. } => {
                if let Some(active) = &mut self.active
                    && !active
                        .udp_seq_tracker
                        .check_and_record(&peer_id, seq, now_unix)
                {
                    return;
                }
                self.mark_peer_offline_and_emit(&peer_id);
            }
            UdpProcessOutcome::Anomaly(anom) => {
                self.emit_anomaly(anom);
            }
            UdpProcessOutcome::Ignored => {}
        }
    }

    pub(super) fn sweep_timed_out_peers(&mut self) {
        let now_unix = current_unix_timestamp();
        let timeout = self.options.peer_timeout_secs;
        let expired_ids: Vec<String> = {
            let Some(active) = &self.active else {
                return;
            };
            active
                .peers
                .list_views()
                .into_iter()
                .filter(|v| v.is_online)
                .filter_map(|v| {
                    let p = active.peers.get(&v.peer_id)?;
                    if p.origin == PeerOrigin::Discovered
                        && now_unix.saturating_sub(p.last_seen_unix) >= timeout
                    {
                        Some(p.peer_id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        for peer_id in expired_ids {
            self.mark_peer_offline_and_emit(&peer_id);
        }
    }

    pub(super) fn mark_peer_offline_and_emit(&mut self, peer_id: &str) {
        let mut events = Vec::new();
        if let Some(active) = &mut self.active {
            let prev = active
                .peers
                .get(peer_id)
                .filter(|p| p.is_online)
                .map(|p| p.display_name.clone());
            let transition = {
                let log_guard = self
                    .shared_log
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                active.peers.mark_offline(peer_id, &log_guard)
            };
            if matches!(
                transition,
                crate::domain::model::OfflineTransition::RemovedEmpty
                    | crate::domain::model::OfflineTransition::MarkedOffline
            ) {
                if let Some(display_name) = prev {
                    events.push(AppEvent::PeerLeft {
                        peer_id: peer_id.to_string(),
                        display_name,
                    });
                }
                events.push(AppEvent::PeerListChanged(active.peers.list_views()));
            }
        }
        for ev in events {
            self.emit(ev);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_inbound_hello(
        &mut self,
        peer_ip: IpAddr,
        sender_id: &str,
        sender_name: &str,
        tcp_port: u16,
        status: UserStatus,
        timestamp: i64,
        seq: u64,
        advertised_ip: Option<IpAddr>,
        now_unix: i64,
    ) {
        if validate_identifier(sender_id).is_err() || validate_port(tcp_port).is_err() || seq == 0 {
            return;
        }
        if let Some(adv) = advertised_ip
            && !adv.is_unspecified()
            && normalize_ip(adv) != normalize_ip(peer_ip)
        {
            if self.allow_anomaly_now(peer_ip) {
                self.emit(AppEvent::AdvertisedIpMismatch {
                    peer_ip,
                    advertised_ip: adv,
                });
            }
            return;
        }
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
        let Ok(clean_name) = validate_and_normalize_display_name(sender_name) else {
            return;
        };

        let mut events = Vec::new();
        if let Some(active) = &mut self.active {
            if sender_id == active.ephemeral_peer_id {
                return;
            }
            if !active
                .hello_seq_tracker
                .check_and_record(sender_id, seq, now_unix)
            {
                return;
            }
            let remote_addr = SocketAddr::new(peer_ip, tcp_port);
            let default_temp_id = format!("manual:{peer_ip}:{tcp_port}");
            let temp_id = active
                .manual_pending_endpoints
                .remove(&remote_addr)
                .or_else(|| {
                    active
                        .peers
                        .get(&default_temp_id)
                        .map(|_| default_temp_id.clone())
                });

            let existing_origin = active.peers.get(sender_id).map(|p| p.origin);
            let origin = if temp_id.is_some() {
                PeerOrigin::Manual
            } else {
                existing_origin.unwrap_or(PeerOrigin::Discovered)
            };
            let was_online = active.peers.get(sender_id).is_some_and(|p| p.is_online);
            let formal = PeerInfo {
                peer_id: sender_id.to_string(),
                display_name: clean_name.clone(),
                ip: peer_ip,
                tcp_port,
                status,
                is_online: true,
                origin,
                last_seen_unix: now_unix,
                unread_count: 0,
            };

            let (upsert_res, merged_thread_len, total_log_bytes) = {
                let mut log_guard = self
                    .shared_log
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let res = if let Some(tid) = temp_id.as_deref() {
                    active.peers.merge_manual_peer(tid, formal, &mut log_guard)
                } else {
                    active.peers.upsert_online_peer(formal, &mut log_guard)
                };
                let tlen = log_guard.thread_len(&ThreadKey::Peer(sender_id.to_string()));
                let total_bytes = log_guard.current_total_bytes();
                (res, tlen, total_bytes)
            };

            match upsert_res {
                Ok(_) => {
                    if !was_online {
                        events.push(AppEvent::PeerJoined {
                            peer_id: sender_id.to_string(),
                            display_name: clean_name,
                        });
                    }
                    if temp_id.is_some() && merged_thread_len > 0 {
                        events.push(AppEvent::ThreadUpdated {
                            thread: ThreadKey::Peer(sender_id.to_string()),
                            new_count: merged_thread_len,
                            total_log_bytes,
                        });
                    }
                    events.push(AppEvent::PeerListChanged(active.peers.list_views()));

                    // 無限ピンポン防止: 直近5秒以内に送信済みでなければ Hello を1回返信
                    let now_inst = Instant::now();
                    let sent_to_peer =
                        active
                            .recent_peer_hello_sent
                            .get(sender_id)
                            .is_some_and(|t| {
                                now_inst.saturating_duration_since(*t) < HELLO_REPLY_COOLDOWN
                            });
                    let sent_to_addr =
                        active.recent_hello_sent.get(&remote_addr).is_some_and(|t| {
                            now_inst.saturating_duration_since(*t) < HELLO_REPLY_COOLDOWN
                        });
                    if !sent_to_peer
                        && !sent_to_addr
                        && let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k))
                    {
                        active
                            .recent_peer_hello_sent
                            .insert(sender_id.to_string(), now_inst);
                        active.recent_hello_sent.insert(remote_addr, now_inst);
                        let reply_seq = active.next_hello_seq();
                        let reply_adv_ip = active.advertised_ip_for_target(Some(remote_addr.ip()));
                        let reply = TcpPayload::Hello {
                            sender_id: active.ephemeral_peer_id.clone(),
                            sender_name: active.display_name.clone(),
                            tcp_port: active.tcp_port,
                            status: active.status,
                            timestamp: current_unix_timestamp(),
                            seq: reply_seq,
                            advertised_ip: reply_adv_ip,
                        };
                        let cancel = active.cancel.clone();
                        active.outbound_tasks.spawn(async move {
                            tokio::select! {
                                _ = cancel.cancelled() => {},
                                _ = send_tcp_control_frame(remote_addr, &msg_key, &reply) => {},
                            }
                        });
                    }
                }
                Err(err) => {
                    events.push(AppEvent::ErrorNotice(err.to_string()));
                }
            }
        }
        for ev in events {
            self.emit(ev);
        }
    }

    pub(super) fn handle_add_manual_peer(
        &mut self,
        host: &str,
        tcp_port: u16,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) {
        let (ip, port) = match validate_manual_peer_endpoint(host, tcp_port) {
            Ok(pair) => pair,
            Err(err) => {
                self.emit(AppEvent::ErrorNotice(err.to_string()));
                return;
            }
        };
        let target_addr = SocketAddr::new(ip, port);

        let Some(active) = &mut self.active else {
            return;
        };
        if active.is_self_endpoint(ip, port) {
            emit_event(
                &self.event_tx,
                &self.wake_ui,
                AppEvent::ErrorNotice("自分自身のアドレスは手動追加できません".to_string()),
            );
            return;
        }

        let existing_formal_id = active
            .peers
            .list_views()
            .into_iter()
            .find(|v| {
                !v.peer_id.starts_with("manual:")
                    && v.tcp_port == port
                    && v.ip_text == ip.to_string()
            })
            .map(|v| v.peer_id);

        let temp_id = existing_formal_id.unwrap_or_else(|| format!("manual:{ip}:{port}"));
        let is_temp = temp_id.starts_with("manual:");

        if is_temp {
            let temp_peer = PeerInfo {
                peer_id: temp_id.clone(),
                display_name: format!("{ip}:{port}"),
                ip,
                tcp_port: port,
                status: UserStatus::Online,
                is_online: true,
                origin: PeerOrigin::Manual,
                last_seen_unix: current_unix_timestamp(),
                unread_count: 0,
            };
            let res = {
                let mut log_guard = self
                    .shared_log
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                active.peers.upsert_online_peer(temp_peer, &mut log_guard)
            };
            if let Err(err) = res {
                emit_event(
                    &self.event_tx,
                    &self.wake_ui,
                    AppEvent::ErrorNotice(err.to_string()),
                );
                return;
            }
            active
                .manual_pending_endpoints
                .insert(target_addr, temp_id.clone());
            emit_event(
                &self.event_tx,
                &self.wake_ui,
                AppEvent::PeerListChanged(active.peers.list_views()),
            );
        }

        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };
        active.recent_hello_sent.insert(target_addr, Instant::now());
        let hello_seq = active.next_hello_seq();
        let advertised_ip = active.advertised_ip_for_target(Some(target_addr.ip()));
        let hello = TcpPayload::Hello {
            sender_id: active.ephemeral_peer_id.clone(),
            sender_name: active.display_name.clone(),
            tcp_port: active.tcp_port,
            status: active.status,
            timestamp: current_unix_timestamp(),
            seq: hello_seq,
            advertised_ip,
        };
        let tx = internal_tx.clone();
        let cancel = active.cancel.clone();
        active.outbound_tasks.spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {},
                res = send_tcp_control_frame(target_addr, &msg_key, &hello) => {
                    let mapped = res.map_err(|e| e.to_string());
                    let _ = tx.send(InternalMsg::ManualHelloFinished {
                        target_addr,
                        temp_id,
                        result: mapped,
                    }).await;
                }
            }
        });
    }

    pub(super) fn handle_refresh_network(&mut self) {
        let Some(active) = &mut self.active else {
            return;
        };
        let (nic_info, tcp_port, udp_port) = if self.options.bind_ip_override.is_none() {
            let next_nic = resolve_active_nic_from_str(self.config.preferred_nic_ip.as_deref());
            if self.options.udp_target_override.is_none() {
                active.udp_target = next_nic
                    .as_ref()
                    .map(|nic| SocketAddr::new(IpAddr::V4(nic.broadcast), self.config.udp_port));
            }
            active.nic_info = next_nic.clone();
            (next_nic, active.tcp_port, active.udp_port)
        } else {
            (active.nic_info.clone(), active.tcp_port, active.udp_port)
        };

        self.emit(AppEvent::NetworkRefreshed {
            nic_info,
            tcp_port,
            udp_port,
        });
        self.send_single_beacon_async();
    }
}
