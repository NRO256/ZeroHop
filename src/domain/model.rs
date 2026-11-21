use std::collections::{HashMap, HashSet};
use std::mem::size_of;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::session_log::SessionLog;

pub const CURRENT_PROTOCOL_VERSION: u16 = 4;
pub const UDP_MAGIC: [u8; 4] = *b"LMSG";
pub const MAX_UDP_PACKET_BYTES: usize = 1200;
pub const MAX_TCP_CONTROL_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_TCP_FILE_CHUNK_FRAME_BYTES: usize = 80 * 1024;
pub const MAX_CHAT_BODY_BYTES: usize = 4096;
pub const MAX_DISPLAY_NAME_CHARS: usize = 32;
pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_MESSAGES_PER_THREAD: usize = 1000;
pub const MAX_TRACKED_PEERS: usize = 64;
pub const DEFAULT_MAX_TOTAL_LOG_BYTES: usize = 16 * 1024 * 1024;
pub const MIN_MAX_MEMORY_MB: u16 = 4;
pub const MAX_MAX_MEMORY_MB: u16 = 32;
pub const DEFAULT_UDP_PORT: u16 = 45100;
pub const DEFAULT_TCP_PORT: u16 = 45101;
pub const MAX_FILE_TRANSFER_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserStatus {
    #[default]
    Online,
    Away,
    Busy,
}

impl UserStatus {
    pub fn label_ja(self) -> &'static str {
        match self {
            Self::Online => "オンライン",
            Self::Away => "離席中",
            Self::Busy => "取り込み中",
        }
    }
}

/// 1対1と全体チャットで分離された到達確認状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryState {
    Received,
    DirectSending,
    DirectDelivered,
    DirectFailed,
    Broadcast {
        target_count: usize,
        acked_peers: HashSet<String>,
        failed_peers: Vec<String>,
    },
}

impl Zeroize for DeliveryState {
    fn zeroize(&mut self) {
        if let Self::Broadcast {
            target_count,
            acked_peers,
            failed_peers,
        } = self
        {
            target_count.zeroize();
            for mut peer_id in acked_peers.drain() {
                peer_id.zeroize();
            }
            for peer_id in failed_peers.iter_mut() {
                peer_id.zeroize();
            }
            failed_peers.clear();
        }
    }
}

impl DeliveryState {
    pub fn new_broadcast(target_count: usize) -> Self {
        Self::Broadcast {
            target_count,
            acked_peers: HashSet::new(),
            failed_peers: Vec::new(),
        }
    }

    pub fn record_ack(&mut self, receiver_id: &str) -> bool {
        match self {
            Self::DirectSending | Self::DirectFailed => {
                *self = Self::DirectDelivered;
                true
            }
            Self::Broadcast {
                acked_peers,
                failed_peers,
                ..
            } => {
                let inserted = acked_peers.insert(receiver_id.to_string());
                let prev_len = failed_peers.len();
                for id in failed_peers
                    .iter_mut()
                    .filter(|id| id.as_str() == receiver_id)
                {
                    id.zeroize();
                }
                failed_peers.retain(|id| !id.is_empty());
                inserted || prev_len != failed_peers.len()
            }
            Self::Received | Self::DirectDelivered => false,
        }
    }

    pub fn mark_failed(&mut self, peer_id: Option<&str>) -> bool {
        match self {
            Self::DirectSending => {
                *self = Self::DirectFailed;
                true
            }
            Self::Broadcast {
                acked_peers,
                failed_peers,
                ..
            } => {
                let Some(id) = peer_id else {
                    return false;
                };
                if acked_peers.contains(id) || failed_peers.iter().any(|existing| existing == id) {
                    return false;
                }
                failed_peers.push(id.to_string());
                true
            }
            Self::Received | Self::DirectDelivered | Self::DirectFailed => false,
        }
    }

    pub fn approx_extra_bytes(&self) -> usize {
        match self {
            Self::Broadcast {
                acked_peers,
                failed_peers,
                ..
            } => {
                let ack_bytes: usize = acked_peers.iter().map(|s| s.len() + 24).sum();
                let fail_bytes: usize = failed_peers.iter().map(|s| s.len() + 24).sum();
                ack_bytes + fail_bytes
            }
            Self::Received | Self::DirectSending | Self::DirectDelivered | Self::DirectFailed => 0,
        }
    }

    pub fn status_label(&self) -> String {
        match self {
            Self::Received => "受信".to_string(),
            Self::DirectSending => "送信中".to_string(),
            Self::DirectDelivered => "送信済み".to_string(),
            Self::DirectFailed => "未達".to_string(),
            Self::Broadcast {
                target_count,
                acked_peers,
                failed_peers,
            } => {
                let acked = acked_peers.len();
                if *target_count == 0 {
                    "送信対象なし".to_string()
                } else if acked >= *target_count {
                    format!("全員到達 ({acked}/{target_count})")
                } else if !failed_peers.is_empty() && acked + failed_peers.len() >= *target_count {
                    format!("一部未達 ({acked}/{target_count})")
                } else if acked > 0 {
                    format!("一部到達 ({acked}/{target_count})")
                } else {
                    format!("送信中 (0/{target_count})")
                }
            }
        }
    }
}

/// スレッド識別子（全体 または 特定 peer_id）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreadKey {
    Broadcast,
    Peer(String),
}

/// セッション限定インメモリ会話メッセージ（Core 単一保持）
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct InMemoryChatMessage {
    pub message_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub body: String,
    pub timestamp: i64,
    pub delivery: DeliveryState,
    pub approx_bytes: usize,
}

impl InMemoryChatMessage {
    pub fn new(
        message_id: impl Into<String>,
        sender_id: impl Into<String>,
        sender_name: impl Into<String>,
        body: impl Into<String>,
        timestamp: i64,
        delivery: DeliveryState,
    ) -> Self {
        let mut msg = Self {
            message_id: message_id.into(),
            sender_id: sender_id.into(),
            sender_name: sender_name.into(),
            body: body.into(),
            timestamp,
            delivery,
            approx_bytes: 0,
        };
        msg.approx_bytes = msg.compute_approx_bytes();
        msg
    }

    pub fn compute_approx_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.message_id.len())
            .saturating_add(self.sender_id.len())
            .saturating_add(self.sender_name.len())
            .saturating_add(self.body.len())
            .saturating_add(self.delivery.approx_extra_bytes())
    }

    pub fn recalculate_approx_bytes(&mut self) -> isize {
        let prev = self.approx_bytes;
        let next = self.compute_approx_bytes();
        self.approx_bytes = next;
        if next >= prev {
            (next - prev).min(isize::MAX as usize) as isize
        } else {
            -((prev - next).min(isize::MAX as usize) as isize)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOrigin {
    Discovered,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PeerInfo {
    pub peer_id: String,
    pub display_name: String,
    #[zeroize(skip)]
    pub ip: IpAddr,
    pub tcp_port: u16,
    #[zeroize(skip)]
    pub status: UserStatus,
    pub is_online: bool,
    #[zeroize(skip)]
    pub origin: PeerOrigin,
    pub last_seen_unix: i64,
    pub unread_count: usize,
}

impl PeerInfo {
    pub fn short_id(&self) -> String {
        self.peer_id.chars().take(8).collect()
    }

    pub fn to_view(&self) -> PeerView {
        PeerView {
            peer_id: self.peer_id.clone(),
            display_name: self.display_name.clone(),
            short_id: self.short_id(),
            ip_text: self.ip.to_string(),
            tcp_port: self.tcp_port,
            status: self.status,
            is_online: self.is_online,
            unread_count: self.unread_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerView {
    pub peer_id: String,
    pub display_name: String,
    pub short_id: String,
    pub ip_text: String,
    pub tcp_port: u16,
    pub status: UserStatus,
    pub is_online: bool,
    pub unread_count: usize,
}

impl PeerView {
    pub fn format_list_label(&self) -> String {
        let state_text = if self.is_online {
            self.status.label_ja()
        } else {
            "オフライン"
        };
        if self.unread_count > 0 {
            format!(
                "{} [{}] ({}) — {}",
                self.display_name, state_text, self.unread_count, self.short_id
            )
        } else {
            format!("{} [{}] — {}", self.display_name, state_text, self.short_id)
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PeerRegistryError {
    #[error("保持ピア上限に達しており、削除可能なオフラインピアがありません")]
    CapacityReached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerUpsertOutcome {
    Inserted,
    Updated,
    InsertedAfterEviction { evicted_peer_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineTransition {
    NotFound,
    RemovedEmpty,
    MarkedOffline,
}

pub struct PeerRegistry {
    max_peers: usize,
    peers: HashMap<String, PeerInfo>,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::with_limit(MAX_TRACKED_PEERS)
    }

    pub fn with_limit(max_peers: usize) -> Self {
        Self {
            max_peers: max_peers.max(1),
            peers: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn get(&self, peer_id: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    pub fn get_mut(&mut self, peer_id: &str) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    pub fn upsert_online_peer(
        &mut self,
        mut peer: PeerInfo,
        log: &mut SessionLog,
    ) -> Result<PeerUpsertOutcome, PeerRegistryError> {
        peer.is_online = true;
        if let Some(existing) = self.peers.get_mut(&peer.peer_id) {
            peer.unread_count = existing.unread_count.max(peer.unread_count);
            *existing = peer;
            return Ok(PeerUpsertOutcome::Updated);
        }

        let mut evicted_id: Option<String> = None;
        if self.peers.len() >= self.max_peers {
            let oldest_offline = self
                .peers
                .values()
                .filter(|p| !p.is_online)
                .min_by(|a, b| {
                    a.last_seen_unix
                        .cmp(&b.last_seen_unix)
                        .then_with(|| a.peer_id.cmp(&b.peer_id))
                })
                .map(|p| p.peer_id.clone());

            let Some(victim_id) = oldest_offline else {
                peer.zeroize();
                return Err(PeerRegistryError::CapacityReached);
            };

            if let Some(mut victim) = self.peers.remove(&victim_id) {
                victim.zeroize();
            }
            let thread_key = ThreadKey::Peer(victim_id.clone());
            log.remove_thread(&thread_key);
            evicted_id = Some(victim_id);
        }

        self.peers.insert(peer.peer_id.clone(), peer);
        match evicted_id {
            Some(evicted_peer_id) => {
                Ok(PeerUpsertOutcome::InsertedAfterEviction { evicted_peer_id })
            }
            None => Ok(PeerUpsertOutcome::Inserted),
        }
    }

    pub fn mark_offline(&mut self, peer_id: &str, log: &SessionLog) -> OfflineTransition {
        let Some(peer) = self.peers.get_mut(peer_id) else {
            return OfflineTransition::NotFound;
        };

        let msg_count = log.thread_len(&ThreadKey::Peer(peer_id.to_string()));
        if msg_count == 0 {
            if let Some(mut removed) = self.peers.remove(peer_id) {
                removed.zeroize();
            }
            OfflineTransition::RemovedEmpty
        } else {
            peer.is_online = false;
            OfflineTransition::MarkedOffline
        }
    }

    pub fn merge_manual_peer(
        &mut self,
        temp_id: &str,
        mut formal: PeerInfo,
        log: &mut SessionLog,
    ) -> Result<PeerUpsertOutcome, PeerRegistryError> {
        if temp_id == formal.peer_id {
            return self.upsert_online_peer(formal, log);
        }

        if let Some(mut temp_peer) = self.peers.remove(temp_id) {
            formal.unread_count = formal.unread_count.saturating_add(temp_peer.unread_count);
            temp_peer.zeroize();
        }
        log.merge_peer_thread(temp_id, &formal.peer_id);
        self.upsert_online_peer(formal, log)
    }

    pub fn list_views(&self) -> Vec<PeerView> {
        let mut views: Vec<PeerView> = self.peers.values().map(PeerInfo::to_view).collect();
        views.sort_by(|a, b| {
            b.is_online
                .cmp(&a.is_online)
                .then_with(|| a.display_name.cmp(&b.display_name))
                .then_with(|| a.peer_id.cmp(&b.peer_id))
        });
        views
    }

    pub fn online_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.is_online).count()
    }

    pub fn clear_all(&mut self) {
        for (_, mut peer) in self.peers.drain() {
            peer.zeroize();
        }
    }
}

impl Drop for PeerRegistry {
    fn drop(&mut self) {
        self.clear_all();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn sample_peer(id: &str, name: &str, last_seen: i64) -> PeerInfo {
        PeerInfo {
            peer_id: id.to_string(),
            display_name: name.to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            tcp_port: 45101,
            status: UserStatus::Online,
            is_online: true,
            origin: PeerOrigin::Discovered,
            last_seen_unix: last_seen,
            unread_count: 0,
        }
    }

    fn sample_msg(id: &str, sender: &str, body: &str, ts: i64) -> InMemoryChatMessage {
        InMemoryChatMessage::new(id, sender, "User", body, ts, DeliveryState::DirectSending)
    }

    #[test]
    fn peer_registry_enforces_64_limit_and_evicts_oldest_offline_with_chat_zeroize() {
        let mut log = SessionLog::new(DEFAULT_MAX_TOTAL_LOG_BYTES);
        let mut registry = PeerRegistry::new();

        for i in 0..MAX_TRACKED_PEERS {
            let id = format!("peer-{i:02}");
            let mut msg = sample_msg(&format!("m-{i}"), &id, "会話履歴あり", 1000 + i as i64);
            msg.delivery = DeliveryState::Received;
            log.push_message(ThreadKey::Peer(id.clone()), msg).unwrap();

            let outcome = registry
                .upsert_online_peer(
                    sample_peer(&id, &format!("User{i:02}"), 100 + i as i64),
                    &mut log,
                )
                .unwrap();
            assert_eq!(outcome, PeerUpsertOutcome::Inserted);
        }
        assert_eq!(registry.len(), 64);

        // 全員オンラインでは65件目が CapacityReached
        let err = registry
            .upsert_online_peer(sample_peer("peer-64", "User64", 9999), &mut log)
            .unwrap_err();
        assert_eq!(err, PeerRegistryError::CapacityReached);
        assert_eq!(registry.len(), 64);

        // peer-02 と peer-05 をオフラインに落とす（会話ありなので保持される）
        assert_eq!(
            registry.mark_offline("peer-02", &log),
            OfflineTransition::MarkedOffline
        );
        assert_eq!(
            registry.mark_offline("peer-05", &log),
            OfflineTransition::MarkedOffline
        );
        assert_eq!(registry.len(), 64);

        // 65件目を追加すると最古オフライン（peer-02）が会話ごと削除される
        let outcome = registry
            .upsert_online_peer(sample_peer("peer-64", "User64", 9999), &mut log)
            .unwrap();
        assert_eq!(
            outcome,
            PeerUpsertOutcome::InsertedAfterEviction {
                evicted_peer_id: "peer-02".to_string()
            }
        );
        assert_eq!(registry.len(), 64);
        assert!(registry.get("peer-02").is_none());
        assert_eq!(log.thread_len(&ThreadKey::Peer("peer-02".to_string())), 0);
        assert!(registry.get("peer-05").is_some());
        assert!(registry.get("peer-64").is_some());
    }

    #[test]
    fn offline_peer_without_chat_is_removed_immediately() {
        let log = SessionLog::new(DEFAULT_MAX_TOTAL_LOG_BYTES);
        let mut registry = PeerRegistry::new();

        registry
            .upsert_online_peer(
                sample_peer("peer-empty", "Empty", 100),
                &mut log.clone_empty_for_test(),
            )
            .unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.mark_offline("peer-empty", &log),
            OfflineTransition::RemovedEmpty
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn merge_manual_peer_migrates_thread_and_unread_count() {
        let mut log = SessionLog::new(DEFAULT_MAX_TOTAL_LOG_BYTES);
        let mut registry = PeerRegistry::new();

        let mut manual = sample_peer("manual:192.168.1.50:45101", "192.168.1.50:45101", 100);
        manual.origin = PeerOrigin::Manual;
        manual.unread_count = 2;
        registry.upsert_online_peer(manual, &mut log).unwrap();

        log.push_message(
            ThreadKey::Peer("manual:192.168.1.50:45101".to_string()),
            sample_msg("m-1", "me", "こんにちは", 100),
        )
        .unwrap();

        let mut formal = sample_peer("uuid-real-1234", "佐藤", 200);
        formal.origin = PeerOrigin::Manual;
        registry
            .merge_manual_peer("manual:192.168.1.50:45101", formal, &mut log)
            .unwrap();

        assert!(registry.get("manual:192.168.1.50:45101").is_none());
        let saved = registry.get("uuid-real-1234").unwrap();
        assert_eq!(saved.display_name, "佐藤");
        assert_eq!(saved.unread_count, 2);
        assert_eq!(
            log.thread_len(&ThreadKey::Peer("manual:192.168.1.50:45101".to_string())),
            0
        );
        assert_eq!(
            log.thread_len(&ThreadKey::Peer("uuid-real-1234".to_string())),
            1
        );
    }

    #[test]
    fn delivery_state_tracks_direct_and_broadcast_acks() {
        let mut direct = DeliveryState::DirectSending;
        assert_eq!(direct.status_label(), "送信中");
        assert!(direct.mark_failed(None));
        assert_eq!(direct.status_label(), "未達");
        assert!(direct.record_ack("peer-1"));
        assert_eq!(direct.status_label(), "送信済み");

        let mut bc = DeliveryState::new_broadcast(2);
        assert_eq!(bc.status_label(), "送信中 (0/2)");
        assert!(bc.record_ack("peer-a"));
        assert_eq!(bc.status_label(), "一部到達 (1/2)");
        assert!(bc.mark_failed(Some("peer-b")));
        assert_eq!(bc.status_label(), "一部未達 (1/2)");
        assert!(bc.record_ack("peer-b"));
        assert_eq!(bc.status_label(), "全員到達 (2/2)");

        bc.zeroize();
        assert_eq!(bc.approx_extra_bytes(), 0);
    }
}
