use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::app::state::{AppEvent, AppStateKind, UiCommand, can_transition};
use crate::crypto::kdf::{
    Argon2Params, SessionKeys, derive_lock_verifier, derive_session_keys_with_params,
};
use crate::crypto::replay::{
    DEFAULT_TIMESTAMP_WINDOW_SECS, ReplayCache, ReplayCheckError, check_timestamp_window,
};
use crate::domain::model::{
    DeliveryState, InMemoryChatMessage, MAX_UDP_PACKET_BYTES, PeerInfo, PeerOrigin, PeerRegistry,
    ThreadKey, UserStatus,
};
use crate::domain::protocol::{TcpPayload, UdpPayload};
use crate::domain::session_log::{SearchHit, SessionLog};
use crate::domain::validation::{
    sanitize_filename, validate_and_normalize_display_name, validate_chat_body, validate_file_size,
    validate_identifier, validate_manual_peer_endpoint, validate_password, validate_port,
    validate_received_chat_body, validate_sha256_hex,
};
use crate::network::nic::{NicInfo, resolve_active_nic_from_str};
use crate::network::rate_limit::{AnomalyRateLimiter, UdpIpRateLimiter};
use crate::network::tcp_transport::{
    InboundTcpEvent, InboundTcpFileChunk, InboundTcpMessage, bind_tcp_listener,
    send_broadcast_control, send_file_chunks_stream, send_tcp_control_frame,
    spawn_tcp_listener_task,
};
use crate::network::udp_discovery::{
    DEFAULT_BEACON_INTERVAL, DEFAULT_NIC_REFRESH_INTERVAL, DEFAULT_PEER_TIMEOUT_SECS,
    UdpProcessOutcome, bind_udp_socket, normalize_ip, process_udp_datagram, send_encrypted_beacon,
    send_encrypted_bye_twice,
};
use crate::network::{AnomalyEvent, current_unix_timestamp};
use crate::storage::cache_wipe::wipe_cache_dir;
use crate::storage::config::{LocalConfig, load_config, save_config};
use crate::storage::paths::AppPaths;
use crate::storage::transfer_store::{EncryptedTransferTempFile, compute_file_sha256_streaming};

const HELLO_REPLY_COOLDOWN: Duration = Duration::from_secs(5);
const PEER_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const COMMAND_CHANNEL_CAPACITY: usize = 128;
const INTERNAL_CHANNEL_CAPACITY: usize = 256;
const MAX_PEER_SEQ_TRACKED: usize = 512;
const PEER_SEQ_TTL_SECS: i64 = DEFAULT_TIMESTAMP_WINDOW_SECS * 2;

struct PeerSeqTracker {
    entries: HashMap<String, (u64, i64)>,
}

impl PeerSeqTracker {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn check_and_record(&mut self, peer_id: &str, seq: u64, now_unix: i64) -> bool {
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

    fn clear(&mut self) {
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

#[derive(Clone)]
pub struct SessionLogReader {
    inner: Arc<RwLock<SessionLog>>,
}

impl SessionLogReader {
    pub fn thread_len(&self, thread: &ThreadKey) -> usize {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.thread_len(thread)
    }

    pub fn with_message<R>(
        &self,
        thread: &ThreadKey,
        index: usize,
        f: impl FnOnce(&InMemoryChatMessage) -> R,
    ) -> Option<R> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get_message(thread, index).map(f)
    }

    pub fn total_bytes(&self) -> usize {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.current_total_bytes()
    }

    pub fn search(
        &self,
        thread_filter: Option<&ThreadKey>,
        query: &str,
        limit: usize,
    ) -> Vec<SearchHit> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.search(thread_filter, query, limit)
    }
}

#[derive(Debug, Clone)]
pub struct CoordinatorOptions {
    pub paths: AppPaths,
    pub argon2_params: Argon2Params,
    pub bind_ip_override: Option<IpAddr>,
    pub preferred_udp_port_override: Option<u16>,
    pub preferred_tcp_port_override: Option<u16>,
    pub udp_target_override: Option<SocketAddr>,
    pub enable_udp_broadcast: bool,
    pub beacon_interval: Duration,
    pub peer_timeout_secs: i64,
    pub nic_refresh_interval: Duration,
}

impl CoordinatorOptions {
    pub fn production(paths: AppPaths) -> Self {
        Self {
            paths,
            argon2_params: Argon2Params::production(),
            bind_ip_override: None,
            preferred_udp_port_override: None,
            preferred_tcp_port_override: None,
            udp_target_override: None,
            enable_udp_broadcast: true,
            beacon_interval: DEFAULT_BEACON_INTERVAL,
            peer_timeout_secs: DEFAULT_PEER_TIMEOUT_SECS,
            nic_refresh_interval: DEFAULT_NIC_REFRESH_INTERVAL,
        }
    }

    pub fn loopback_for_test(paths: AppPaths) -> Self {
        Self {
            paths,
            argon2_params: Argon2Params {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
            },
            bind_ip_override: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            preferred_udp_port_override: Some(0),
            preferred_tcp_port_override: Some(0),
            udp_target_override: None,
            enable_udp_broadcast: false,
            beacon_interval: Duration::from_secs(10),
            peer_timeout_secs: DEFAULT_PEER_TIMEOUT_SECS,
            nic_refresh_interval: Duration::from_secs(300),
        }
    }
}

pub struct AppHandle {
    pub cmd_tx: mpsc::Sender<UiCommand>,
    pub log_reader: SessionLogReader,
    pub join_handle: JoinHandle<()>,
}

enum InternalMsg {
    UdpDatagram {
        src_addr: SocketAddr,
        data: Vec<u8>,
    },
    TcpInbound(InboundTcpEvent),
    BeaconTick,
    SweepTick,
    NicRefreshTick,
    DirectSendFinished {
        thread: ThreadKey,
        message_id: String,
        result: Result<(), String>,
    },
    BroadcastSendFinished {
        thread: ThreadKey,
        message_id: String,
        failures: Vec<(String, String)>,
    },
    ManualHelloFinished {
        target_addr: SocketAddr,
        temp_id: String,
        result: Result<(), String>,
    },
    UnlockCheckFinished {
        candidate: Option<Zeroizing<[u8; 32]>>,
    },
    FileOfferSendFinished {
        transfer_id: String,
        result: Result<(), String>,
    },
    FileStreamProgress {
        transfer_id: String,
        transferred_bytes: u64,
    },
    FileStreamSendFinished {
        transfer_id: String,
        result: Result<(), String>,
    },
}

struct OutboundTransferState {
    peer_id: String,
    peer_addr: SocketAddr,
    filename: String,
    file_path: PathBuf,
    file_size: u64,
    accepted: bool,
    cancel_token: CancellationToken,
}

struct PendingInboundOffer {
    peer_id: String,
    peer_addr: SocketAddr,
    filename: String,
    file_size: u64,
    sha256_hex: String,
}

struct ActiveInboundTransfer {
    peer_id: String,
    filename: String,
    expected_size: u64,
    expected_sha256_hex: String,
    save_path: PathBuf,
    temp_file: EncryptedTransferTempFile,
    last_reported_bytes: u64,
}

struct ActiveSession {
    display_name: String,
    ephemeral_peer_id: String,
    status: UserStatus,
    keys: SessionKeys,
    bind_ip: IpAddr,
    udp_socket: Arc<UdpSocket>,
    udp_port: u16,
    tcp_port: u16,
    nic_info: Option<NicInfo>,
    udp_target: Option<SocketAddr>,
    peers: PeerRegistry,
    replay: ReplayCache,
    next_udp_seq: u64,
    next_hello_seq: u64,
    udp_seq_tracker: PeerSeqTracker,
    hello_seq_tracker: PeerSeqTracker,
    recent_hello_sent: HashMap<SocketAddr, Instant>,
    recent_peer_hello_sent: HashMap<String, Instant>,
    manual_pending_endpoints: HashMap<SocketAddr, String>,
    udp_ip_limiter: UdpIpRateLimiter,
    anomaly_limiter: Arc<AsyncMutex<AnomalyRateLimiter>>,
    cancel: CancellationToken,
    worker_handles: Vec<JoinHandle<()>>,
    outbound_tasks: JoinSet<()>,
    outbound_transfers: HashMap<String, OutboundTransferState>,
    pending_inbound_offers: HashMap<String, PendingInboundOffer>,
    active_inbound_transfers: HashMap<String, ActiveInboundTransfer>,
}

impl ActiveSession {
    fn next_udp_seq(&mut self) -> u64 {
        let s = self.next_udp_seq.max(1);
        self.next_udp_seq = s.saturating_add(1);
        s
    }

    fn next_hello_seq(&mut self) -> u64 {
        let s = self.next_hello_seq.max(1);
        self.next_hello_seq = s.saturating_add(1);
        s
    }

    fn advertised_ip_for_target(&self, target: Option<IpAddr>) -> Option<IpAddr> {
        let base = if let Some(t) = target
            && t.is_loopback()
        {
            Some(t)
        } else if !self.bind_ip.is_unspecified() {
            Some(self.bind_ip)
        } else {
            self.nic_info.as_ref().map(|nic| IpAddr::V4(nic.ip))
        };
        match (base, target) {
            (Some(b), Some(t)) if b.is_ipv4() != t.is_ipv4() => None,
            (b, _) => b,
        }
    }

    fn is_self_endpoint(&self, ip: IpAddr, port: u16) -> bool {
        if port != self.tcp_port {
            return false;
        }
        let norm_ip = normalize_ip(ip);
        if norm_ip == normalize_ip(self.bind_ip) {
            return true;
        }
        if norm_ip.is_loopback() && (self.bind_ip.is_unspecified() || self.bind_ip.is_loopback()) {
            return true;
        }
        self.nic_info
            .as_ref()
            .is_some_and(|nic| IpAddr::V4(nic.ip) == norm_ip)
    }

    fn wipe_in_memory(&mut self) {
        self.display_name.zeroize();
        self.ephemeral_peer_id.zeroize();
        for (_, tr) in self.outbound_transfers.drain() {
            tr.cancel_token.cancel();
        }
        self.pending_inbound_offers.clear();
        self.active_inbound_transfers.clear();
        self.peers.clear_all();
        self.replay.clear();
        self.udp_seq_tracker.clear();
        self.hello_seq_tracker.clear();
        self.keys.zeroize_now();
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.wipe_in_memory();
    }
}

pub fn spawn_coordinator(
    options: CoordinatorOptions,
    event_tx: std::sync::mpsc::Sender<AppEvent>,
    wake_ui: Arc<dyn Fn() + Send + Sync>,
) -> AppHandle {
    let initial_cfg = load_config(&options.paths).into_config();
    let shared_log = Arc::new(RwLock::new(SessionLog::new(
        initial_cfg.max_total_log_bytes(),
    )));
    let log_reader = SessionLogReader {
        inner: Arc::clone(&shared_log),
    };

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let coordinator = Coordinator {
        options,
        state: AppStateKind::LoggedOut,
        config: initial_cfg,
        shared_log,
        event_tx,
        wake_ui,
        active: None,
    };

    let join_handle = tokio::spawn(coordinator.run(cmd_rx));
    AppHandle {
        cmd_tx,
        log_reader,
        join_handle,
    }
}

struct Coordinator {
    options: CoordinatorOptions,
    state: AppStateKind,
    config: LocalConfig,
    shared_log: Arc<RwLock<SessionLog>>,
    event_tx: std::sync::mpsc::Sender<AppEvent>,
    wake_ui: Arc<dyn Fn() + Send + Sync>,
    active: Option<ActiveSession>,
}

fn emit_event(
    event_tx: &std::sync::mpsc::Sender<AppEvent>,
    wake_ui: &Arc<dyn Fn() + Send + Sync>,
    event: AppEvent,
) {
    let _ = event_tx.send(event);
    wake_ui();
}

fn allow_anomaly_for(active: &ActiveSession, peer_ip: IpAddr) -> bool {
    if let Ok(mut guard) = active.anomaly_limiter.try_lock() {
        guard.allow_at(peer_ip, Instant::now())
    } else {
        false
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
    fn emit(&self, event: AppEvent) {
        emit_event(&self.event_tx, &self.wake_ui, event);
    }

    fn set_state(&mut self, next: AppStateKind) {
        if can_transition(self.state, next) {
            self.state = next;
        }
    }

    async fn run(mut self, mut cmd_rx: mpsc::Receiver<UiCommand>) {
        let (internal_tx, mut internal_rx) =
            mpsc::channel::<InternalMsg>(INTERNAL_CHANNEL_CAPACITY);

        loop {
            tokio::select! {
                maybe_cmd = cmd_rx.recv() => {
                    let Some(cmd) = maybe_cmd else {
                        self.perform_logout_or_shutdown(true).await;
                        break;
                    };
                    let should_exit = self.handle_ui_command(cmd, &mut cmd_rx, &internal_tx).await;
                    if should_exit {
                        break;
                    }
                }
                maybe_internal = internal_rx.recv() => {
                    if let Some(msg) = maybe_internal {
                        self.handle_internal_msg(msg, &internal_tx);
                    }
                }
            }
        }
    }

    async fn handle_ui_command(
        &mut self,
        cmd: UiCommand,
        cmd_rx: &mut mpsc::Receiver<UiCommand>,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) -> bool {
        match cmd {
            UiCommand::LoginRequest {
                display_name,
                password,
            } => {
                if self.state != AppStateKind::LoggedOut {
                    self.emit(AppEvent::LoginFailed {
                        reason: "すでにログイン中またはログイン処理中です".to_string(),
                    });
                    return false;
                }
                self.handle_login(display_name, password, cmd_rx, internal_tx)
                    .await
            }
            UiCommand::CancelLogin => false,
            UiCommand::SendChat { thread, body } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_send_chat(thread, body, internal_tx);
                }
                false
            }
            UiCommand::RetryChat { thread, message_id } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_retry_chat(thread, message_id, internal_tx);
                }
                false
            }
            UiCommand::AddManualPeer { host, tcp_port } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_add_manual_peer(&host, tcp_port, internal_tx);
                }
                false
            }
            UiCommand::RefreshNetwork => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_refresh_network();
                }
                false
            }
            UiCommand::ChangeStatus(new_status) => {
                if self.state == AppStateKind::LoggedIn
                    && let Some(active) = &mut self.active
                {
                    active.status = new_status;
                    self.emit(AppEvent::StatusChanged(new_status));
                    self.send_single_beacon_async();
                }
                false
            }
            UiCommand::ClearSessionChat { thread } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_clear_session_chat(thread);
                }
                false
            }
            UiCommand::SendFile { peer_id, file_path } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_send_file(peer_id, file_path, internal_tx);
                }
                false
            }
            UiCommand::RespondFileOffer {
                transfer_id,
                accept,
                save_path,
            } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_respond_file_offer(transfer_id, accept, save_path);
                }
                false
            }
            UiCommand::CancelFileTransfer { transfer_id } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_cancel_file_transfer(&transfer_id);
                }
                false
            }
            UiCommand::UpdateConfig(mut new_cfg) => {
                new_cfg.sanitize();
                self.config = new_cfg.clone();
                let new_limit = self.config.max_total_log_bytes();
                let evicted = {
                    let mut guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.set_max_total_bytes(new_limit)
                };
                if evicted > 0 && self.active.is_some() {
                    let count = {
                        let guard = self
                            .shared_log
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        guard.thread_len(&ThreadKey::Broadcast)
                    };
                    self.emit(AppEvent::ThreadUpdated {
                        thread: ThreadKey::Broadcast,
                        new_count: count,
                        total_log_bytes: self.current_log_bytes(),
                    });
                }
                if let Err(err) = save_config(&self.options.paths, &new_cfg) {
                    self.emit(AppEvent::ErrorNotice(format!(
                        "設定の保存に失敗しました: {err}"
                    )));
                }
                false
            }
            UiCommand::LockScreen => {
                if self.state == AppStateKind::LoggedIn && self.active.is_some() {
                    self.set_state(AppStateKind::Locked);
                    self.emit(AppEvent::ScreenLocked);
                }
                false
            }
            UiCommand::UnlockScreen { password } => {
                if self.state == AppStateKind::Locked && self.active.is_some() {
                    let params = self.options.argon2_params;
                    let tx = internal_tx.clone();
                    tokio::spawn(async move {
                        let candidate = tokio::task::spawn_blocking(move || {
                            derive_lock_verifier(&password, params).ok()
                        })
                        .await
                        .ok()
                        .flatten();
                        let _ = tx
                            .send(InternalMsg::UnlockCheckFinished { candidate })
                            .await;
                    });
                }
                false
            }
            UiCommand::Logout => {
                self.perform_logout_or_shutdown(false).await;
                false
            }
            UiCommand::Shutdown => {
                self.perform_logout_or_shutdown(true).await;
                true
            }
        }
    }

    async fn handle_login(
        &mut self,
        raw_display_name: String,
        password: Zeroizing<String>,
        cmd_rx: &mut mpsc::Receiver<UiCommand>,
        internal_tx: &mpsc::Sender<InternalMsg>,
    ) -> bool {
        let display_name = match validate_and_normalize_display_name(&raw_display_name) {
            Ok(name) => name,
            Err(err) => {
                self.emit(AppEvent::LoginFailed {
                    reason: err.to_string(),
                });
                return false;
            }
        };
        if let Err(err) = validate_password(&password) {
            self.emit(AppEvent::LoginFailed {
                reason: err.to_string(),
            });
            return false;
        }

        self.set_state(AppStateKind::Authenticating);
        let argon2_params = self.options.argon2_params;
        let mut kdf_handle = tokio::task::spawn_blocking(move || {
            derive_session_keys_with_params(&password, argon2_params)
        });

        let mut cancelled = false;
        let mut shutdown_requested = false;
        let kdf_result = loop {
            tokio::select! {
                res = &mut kdf_handle => break Some(res),
                maybe_cmd = cmd_rx.recv() => {
                    match maybe_cmd {
                        Some(UiCommand::CancelLogin) => {
                            cancelled = true;
                            break None;
                        }
                        Some(UiCommand::Shutdown) | None => {
                            shutdown_requested = true;
                            break None;
                        }
                        Some(_) => {}
                    }
                }
            }
        };

        if shutdown_requested {
            // バックグラウンドで導出された鍵も確実にゼロ化して破棄する
            tokio::spawn(async move {
                if let Ok(Ok(keys)) = kdf_handle.await {
                    keys.zeroize_now();
                }
            });
            self.set_state(AppStateKind::Exiting);
            self.emit(AppEvent::ShutdownReady);
            return true;
        }

        if cancelled {
            tokio::spawn(async move {
                if let Ok(Ok(keys)) = kdf_handle.await {
                    keys.zeroize_now();
                }
            });
            self.set_state(AppStateKind::LoggedOut);
            self.emit(AppEvent::LoginFailed {
                reason: "ログインをキャンセルしました".to_string(),
            });
            return false;
        }

        let keys = match kdf_result.expect("kdf_result must be Some when not cancelled") {
            Ok(Ok(keys)) => keys,
            Ok(Err(err)) => {
                self.set_state(AppStateKind::LoggedOut);
                self.emit(AppEvent::LoginFailed {
                    reason: err.to_string(),
                });
                return false;
            }
            Err(join_err) => {
                self.set_state(AppStateKind::LoggedOut);
                self.emit(AppEvent::LoginFailed {
                    reason: format!("鍵導出タスクエラー: {join_err}"),
                });
                return false;
            }
        };

        let nic_info = if self.options.bind_ip_override.is_none() {
            resolve_active_nic_from_str(self.config.preferred_nic_ip.as_deref())
        } else {
            None
        };
        let bind_ip = self.options.bind_ip_override.unwrap_or_else(|| {
            nic_info
                .as_ref()
                .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |n| IpAddr::V4(n.ip))
        });

        let pref_tcp = self
            .options
            .preferred_tcp_port_override
            .unwrap_or(self.config.tcp_port);
        let (tcp_listener, tcp_port) = match bind_tcp_listener(bind_ip, pref_tcp).await {
            Ok(pair) => pair,
            Err(err) => {
                keys.zeroize_now();
                self.set_state(AppStateKind::LoggedOut);
                self.emit(AppEvent::LoginFailed {
                    reason: format!("TCPポート確保失敗: {err}"),
                });
                return false;
            }
        };

        let pref_udp = self
            .options
            .preferred_udp_port_override
            .unwrap_or(self.config.udp_port);
        let udp_bind_addr = SocketAddr::new(bind_ip, pref_udp);
        let (udp_socket, udp_port) =
            match bind_udp_socket(udp_bind_addr, self.options.enable_udp_broadcast) {
                Ok(pair) => pair,
                Err(err) => {
                    drop(tcp_listener);
                    keys.zeroize_now();
                    self.set_state(AppStateKind::LoggedOut);
                    self.emit(AppEvent::LoginFailed {
                        reason: format!("UDPポート確保失敗: {err}"),
                    });
                    return false;
                }
            };

        let udp_target = self.options.udp_target_override.or_else(|| {
            nic_info
                .as_ref()
                .map(|nic| SocketAddr::new(IpAddr::V4(nic.broadcast), self.config.udp_port))
        });

        {
            let mut log_guard = self
                .shared_log
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = log_guard.clear_all();
            let _ = log_guard.set_max_total_bytes(self.config.max_total_log_bytes());
        }

        let ephemeral_peer_id = Uuid::new_v4().to_string();
        let room_code = keys.room_code();
        let cancel = CancellationToken::new();
        let anomaly_limiter = Arc::new(AsyncMutex::new(AnomalyRateLimiter::default_anomaly()));

        let msg_key = match keys.with_msg_key(|k| Zeroizing::new(*k)) {
            Ok(k) => k,
            Err(err) => {
                keys.zeroize_now();
                self.set_state(AppStateKind::LoggedOut);
                self.emit(AppEvent::LoginFailed {
                    reason: err.to_string(),
                });
                return false;
            }
        };

        let mut worker_handles = Vec::new();

        // 1. TCP 待受タスク
        let (tcp_in_tx, mut tcp_in_rx) = mpsc::channel::<InboundTcpEvent>(128);
        let tcp_handle = spawn_tcp_listener_task(
            tcp_listener,
            msg_key,
            tcp_in_tx,
            Arc::clone(&anomaly_limiter),
            cancel.clone(),
        );
        worker_handles.push(tcp_handle);

        let tcp_bridge_tx = internal_tx.clone();
        let tcp_bridge_cancel = cancel.clone();
        worker_handles.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tcp_bridge_cancel.cancelled() => break,
                    maybe_ev = tcp_in_rx.recv() => {
                        let Some(ev) = maybe_ev else { break; };
                        if tcp_bridge_tx.send(InternalMsg::TcpInbound(ev)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }));

        // 2. UDP 受信タスク
        let udp_recv_sock = Arc::clone(&udp_socket);
        let udp_tx = internal_tx.clone();
        let udp_cancel = cancel.clone();
        worker_handles.push(tokio::spawn(async move {
            let mut buf = [0u8; MAX_UDP_PACKET_BYTES + 64];
            loop {
                tokio::select! {
                    _ = udp_cancel.cancelled() => break,
                    res = udp_recv_sock.recv_from(&mut buf) => {
                        match res {
                            Ok((len, src_addr)) => {
                                let data = buf[..len].to_vec();
                                if udp_tx.send(InternalMsg::UdpDatagram { src_addr, data }).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                if udp_cancel.is_cancelled() {
                                    break;
                                }
                                if matches!(
                                    err.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::Interrupted
                                        | std::io::ErrorKind::WouldBlock
                                ) {
                                    continue;
                                }
                                tokio::select! {
                                    _ = udp_cancel.cancelled() => break,
                                    _ = tokio::time::sleep(Duration::from_millis(50)) => continue,
                                }
                            }
                        }
                    }
                }
            }
        }));

        // 3. 定期タイマー群（Beacon / タイムアウト監視 / NIC再検出）
        let beacon_interval = self.options.beacon_interval;
        let nic_interval = self.options.nic_refresh_interval;
        let timer_tx = internal_tx.clone();
        let timer_cancel = cancel.clone();
        worker_handles.push(tokio::spawn(async move {
            let mut beacon_tick = tokio::time::interval(beacon_interval);
            beacon_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut sweep_tick = tokio::time::interval(PEER_SWEEP_INTERVAL);
            sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut nic_tick = tokio::time::interval(nic_interval);
            nic_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // 初回即時発火を消費（ログイン直後1回は手動で即時発火するため）
            beacon_tick.tick().await;
            sweep_tick.tick().await;
            nic_tick.tick().await;

            loop {
                tokio::select! {
                    _ = timer_cancel.cancelled() => break,
                    _ = beacon_tick.tick() => {
                        let _ = timer_tx.send(InternalMsg::BeaconTick).await;
                    }
                    _ = sweep_tick.tick() => {
                        let _ = timer_tx.send(InternalMsg::SweepTick).await;
                    }
                    _ = nic_tick.tick() => {
                        let _ = timer_tx.send(InternalMsg::NicRefreshTick).await;
                    }
                }
            }
        }));

        self.active = Some(ActiveSession {
            display_name: display_name.clone(),
            ephemeral_peer_id: ephemeral_peer_id.clone(),
            status: UserStatus::Online,
            keys,
            bind_ip,
            udp_socket,
            udp_port,
            tcp_port,
            nic_info: nic_info.clone(),
            udp_target,
            peers: PeerRegistry::new(),
            replay: ReplayCache::new(),
            next_udp_seq: 1,
            next_hello_seq: 1,
            udp_seq_tracker: PeerSeqTracker::new(),
            hello_seq_tracker: PeerSeqTracker::new(),
            recent_hello_sent: HashMap::new(),
            recent_peer_hello_sent: HashMap::new(),
            manual_pending_endpoints: HashMap::new(),
            udp_ip_limiter: UdpIpRateLimiter::default_udp(),
            anomaly_limiter,
            cancel,
            worker_handles,
            outbound_tasks: JoinSet::new(),
            outbound_transfers: HashMap::new(),
            pending_inbound_offers: HashMap::new(),
            active_inbound_transfers: HashMap::new(),
        });

        self.set_state(AppStateKind::LoggedIn);
        self.emit(AppEvent::LoginSucceeded {
            display_name,
            room_code,
            ephemeral_peer_id,
            tcp_port,
            udp_port,
            nic_info,
        });

        // ログイン直後に暗号化ビーコンを1回送出
        self.send_single_beacon_async();
        false
    }

    fn current_log_bytes(&self) -> usize {
        let guard = self
            .shared_log
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.current_total_bytes()
    }

    fn send_single_beacon_async(&mut self) {
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
        let sock = Arc::clone(&active.udp_socket);
        let payload = UdpPayload::Beacon {
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

    fn handle_internal_msg(&mut self, msg: InternalMsg, internal_tx: &mpsc::Sender<InternalMsg>) {
        if let Some(active) = &mut self.active {
            while let Some(joined) = active.outbound_tasks.try_join_next() {
                let _ = joined;
            }
        }

        match msg {
            InternalMsg::UdpDatagram { src_addr, data } => {
                self.handle_udp_datagram(src_addr, &data);
            }
            InternalMsg::TcpInbound(ev) => match ev {
                InboundTcpEvent::Payload(msg) => self.handle_inbound_tcp(msg, internal_tx),
                InboundTcpEvent::FileChunk(chunk) => self.handle_inbound_file_chunk(chunk),
                InboundTcpEvent::FileStreamClosed {
                    peer_ip: _,
                    transfer_id,
                } => self.handle_inbound_file_stream_closed(&transfer_id),
                InboundTcpEvent::Anomaly(anom) => self.emit_anomaly(anom),
            },
            InternalMsg::BeaconTick => {
                self.send_single_beacon_async();
            }
            InternalMsg::SweepTick => {
                self.sweep_timed_out_peers();
            }
            InternalMsg::NicRefreshTick => {
                if self.options.bind_ip_override.is_none() {
                    self.handle_refresh_network();
                }
            }
            InternalMsg::DirectSendFinished {
                thread,
                message_id,
                result,
            } => {
                if let Err(reason) = result {
                    let updated = {
                        let mut guard = self
                            .shared_log
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        guard.mark_delivery_failed(&thread, &message_id, None)
                    };
                    if updated {
                        self.emit(AppEvent::DeliveryUpdated { thread, message_id });
                    }
                    self.emit(AppEvent::ErrorNotice(format!(
                        "送信に失敗しました。ファイアウォールまたはポート番号を確認してください: {reason}"
                    )));
                }
            }
            InternalMsg::BroadcastSendFinished {
                thread,
                message_id,
                failures,
            } => {
                if !failures.is_empty() {
                    let mut any_updated = false;
                    {
                        let mut guard = self
                            .shared_log
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        for (peer_id, _) in &failures {
                            if guard.mark_delivery_failed(&thread, &message_id, Some(peer_id)) {
                                any_updated = true;
                            }
                        }
                    }
                    if any_updated {
                        self.emit(AppEvent::DeliveryUpdated { thread, message_id });
                    }
                }
            }
            InternalMsg::ManualHelloFinished {
                target_addr,
                temp_id,
                result,
            } => {
                if let Err(reason) = result {
                    let mut list_changed = false;
                    if let Some(active) = &mut self.active {
                        active.manual_pending_endpoints.remove(&target_addr);
                        let log_guard = self
                            .shared_log
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if matches!(
                            active.peers.mark_offline(&temp_id, &log_guard),
                            crate::domain::model::OfflineTransition::RemovedEmpty
                                | crate::domain::model::OfflineTransition::MarkedOffline
                        ) {
                            list_changed = true;
                        }
                    }
                    if list_changed && let Some(active) = &self.active {
                        self.emit(AppEvent::PeerListChanged(active.peers.list_views()));
                    }
                    self.emit(AppEvent::ErrorNotice(format!(
                        "手動ピア接続に失敗しました。ファイアウォールまたはポート番号を確認してください: {reason}"
                    )));
                }
            }
            InternalMsg::UnlockCheckFinished { candidate } => {
                let ok = if self.state == AppStateKind::Locked
                    && let (Some(active), Some(cand)) = (&self.active, candidate.as_ref())
                {
                    active.keys.verify_lock_verifier(cand)
                } else {
                    false
                };
                if ok {
                    self.set_state(AppStateKind::LoggedIn);
                }
                self.emit(AppEvent::ScreenUnlockResult { ok });
            }
            InternalMsg::FileOfferSendFinished {
                transfer_id,
                result,
            } => {
                if let Err(reason) = result {
                    self.finish_outbound_transfer_with_error(
                        &transfer_id,
                        format!("ファイル送信要求に失敗しました: {reason}"),
                    );
                }
            }
            InternalMsg::FileStreamProgress {
                transfer_id,
                transferred_bytes,
            } => {
                if let Some(active) = &self.active
                    && let Some(tr) = active.outbound_transfers.get(&transfer_id)
                {
                    self.emit(AppEvent::FileTransferProgress {
                        transfer_id,
                        peer_id: tr.peer_id.clone(),
                        filename: tr.filename.clone(),
                        is_sending: true,
                        transferred_bytes,
                        total_bytes: tr.file_size,
                    });
                }
            }
            InternalMsg::FileStreamSendFinished {
                transfer_id,
                result,
            } => {
                self.handle_file_stream_send_finished(&transfer_id, result);
            }
        }
    }

    fn emit_anomaly(&self, anom: AnomalyEvent) {
        match anom {
            AnomalyEvent::KeyMismatch { peer_ip } => {
                self.emit(AppEvent::KeyMismatchDetected { peer_ip });
            }
            AnomalyEvent::ClockSkew {
                peer_ip,
                skew_seconds,
            } => {
                self.emit(AppEvent::ClockSkewDetected {
                    peer_ip,
                    skew_seconds,
                });
            }
            AnomalyEvent::ProtocolVersionMismatch {
                peer_ip,
                received_version,
            } => {
                self.emit(AppEvent::ProtocolVersionMismatch {
                    peer_ip,
                    received_version,
                });
            }
        }
    }

    fn allow_anomaly_now(&self, peer_ip: IpAddr) -> bool {
        let Some(active) = &self.active else {
            return false;
        };
        if let Ok(mut guard) = active.anomaly_limiter.try_lock() {
            guard.allow_at(peer_ip, Instant::now())
        } else {
            false
        }
    }

    fn handle_udp_datagram(&mut self, src_addr: SocketAddr, data: &[u8]) {
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

    fn sweep_timed_out_peers(&mut self) {
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

    fn mark_peer_offline_and_emit(&mut self, peer_id: &str) {
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

    fn handle_inbound_tcp(
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
                if validate_identifier(sender_id).is_err()
                    || validate_port(*tcp_port).is_err()
                    || *seq == 0
                {
                    return;
                }
                if let Some(adv) = advertised_ip
                    && !adv.is_unspecified()
                    && normalize_ip(*adv) != normalize_ip(msg.peer_ip)
                {
                    return;
                }
                if let Err(skew_seconds) =
                    check_timestamp_window(*timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
                {
                    if self.allow_anomaly_now(msg.peer_ip) {
                        self.emit(AppEvent::ClockSkewDetected {
                            peer_ip: msg.peer_ip,
                            skew_seconds,
                        });
                    }
                    return;
                }
                let Ok(clean_name) = validate_and_normalize_display_name(sender_name) else {
                    return;
                };

                let tcp_port = *tcp_port;
                let status = *status;
                let seq = *seq;
                let mut events = Vec::new();
                if let Some(active) = &mut self.active {
                    if sender_id == &active.ephemeral_peer_id {
                        return;
                    }
                    if !active
                        .hello_seq_tracker
                        .check_and_record(sender_id, seq, now_unix)
                    {
                        return;
                    }
                    let remote_addr = SocketAddr::new(msg.peer_ip, tcp_port);
                    let default_temp_id = format!("manual:{}:{}", msg.peer_ip, tcp_port);
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
                        peer_id: sender_id.clone(),
                        display_name: clean_name.clone(),
                        ip: msg.peer_ip,
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
                        let tlen = log_guard.thread_len(&ThreadKey::Peer(sender_id.clone()));
                        let total_bytes = log_guard.current_total_bytes();
                        (res, tlen, total_bytes)
                    };

                    match upsert_res {
                        Ok(_) => {
                            if !was_online {
                                events.push(AppEvent::PeerJoined {
                                    peer_id: sender_id.clone(),
                                    display_name: clean_name,
                                });
                            }
                            if temp_id.is_some() && merged_thread_len > 0 {
                                events.push(AppEvent::ThreadUpdated {
                                    thread: ThreadKey::Peer(sender_id.clone()),
                                    new_count: merged_thread_len,
                                    total_log_bytes,
                                });
                            }
                            events.push(AppEvent::PeerListChanged(active.peers.list_views()));

                            // 無限ピンポン防止: 直近5秒以内に送信済みでなければ Hello を1回返信
                            let now_inst = Instant::now();
                            let sent_to_peer = active
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
                                && let Ok(msg_key) =
                                    active.keys.with_msg_key(|k| Zeroizing::new(*k))
                            {
                                active
                                    .recent_peer_hello_sent
                                    .insert(sender_id.clone(), now_inst);
                                active.recent_hello_sent.insert(remote_addr, now_inst);
                                let reply_seq = active.next_hello_seq();
                                let reply_adv_ip =
                                    active.advertised_ip_for_target(Some(remote_addr.ip()));
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
            TcpPayload::Chat {
                message_id,
                sender_id,
                sender_name,
                is_broadcast,
                body,
                timestamp,
            } => {
                let mut events = Vec::new();
                if let Some(active) = &mut self.active {
                    if sender_id == &active.ephemeral_peer_id
                        || validate_identifier(sender_id).is_err()
                        || validate_identifier(message_id).is_err()
                    {
                        return;
                    }

                    match active
                        .replay
                        .check_and_record(sender_id, message_id, *timestamp, now_unix)
                    {
                        Ok(()) => {}
                        Err(ReplayCheckError::ClockSkew { skew_seconds }) => {
                            if allow_anomaly_for(active, msg.peer_ip) {
                                emit_event(
                                    &self.event_tx,
                                    &self.wake_ui,
                                    AppEvent::ClockSkewDetected {
                                        peer_ip: msg.peer_ip,
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

                    let thread = if *is_broadcast {
                        ThreadKey::Broadcast
                    } else {
                        ThreadKey::Peer(sender_id.clone())
                    };
                    let preview: String = clean_body
                        .replace(['\r', '\n'], " ")
                        .chars()
                        .take(60)
                        .collect();
                    let chat_msg = InMemoryChatMessage::new(
                        message_id.clone(),
                        sender_id.clone(),
                        clean_name.clone(),
                        clean_body,
                        *timestamp,
                        DeliveryState::Received,
                    );

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
                        });
                        spawn_ack_reply_for(active, sender_id, message_id);
                    }
                }
                for ev in events {
                    self.emit(ev);
                }
            }
            TcpPayload::Ack {
                message_id,
                receiver_id,
                timestamp,
            } => {
                if let Err(skew_seconds) =
                    check_timestamp_window(*timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
                {
                    if self.allow_anomaly_now(msg.peer_ip) {
                        self.emit(AppEvent::ClockSkewDetected {
                            peer_ip: msg.peer_ip,
                            skew_seconds,
                        });
                    }
                    return;
                }
                if validate_identifier(message_id).is_err()
                    || validate_identifier(receiver_id).is_err()
                {
                    return;
                }

                let updated_thread = {
                    let mut log_guard = self
                        .shared_log
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let peer_thread = ThreadKey::Peer(receiver_id.clone());
                    if log_guard.update_delivery_ack(&peer_thread, message_id, receiver_id) {
                        Some(peer_thread)
                    } else if log_guard.update_delivery_ack(
                        &ThreadKey::Broadcast,
                        message_id,
                        receiver_id,
                    ) {
                        Some(ThreadKey::Broadcast)
                    } else {
                        None
                    }
                };

                if let Some(thread) = updated_thread {
                    self.emit(AppEvent::DeliveryUpdated {
                        thread,
                        message_id: message_id.clone(),
                    });
                }
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
        }
    }

    fn handle_add_manual_peer(
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

    fn handle_send_chat(
        &mut self,
        thread: ThreadKey,
        raw_body: Zeroizing<String>,
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
                );
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

                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: false,
                    body: (*body).clone(),
                    timestamp: now_unix,
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
                );
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

                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: true,
                    body: (*body).clone(),
                    timestamp: now_unix,
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

    fn handle_retry_chat(
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
                    Some((m.body.clone(), m.timestamp, m.delivery.clone()))
                } else {
                    None
                }
            })
        };

        let Some((body, timestamp, delivery)) = found else {
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
                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: false,
                    body,
                    timestamp,
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

                let payload = TcpPayload::Chat {
                    message_id: message_id.clone(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    sender_name: active.display_name.clone(),
                    is_broadcast: true,
                    body,
                    timestamp,
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

    fn handle_clear_session_chat(&self, thread: Option<ThreadKey>) {
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

    fn handle_refresh_network(&mut self) {
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

    fn handle_send_file(
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

    fn handle_respond_file_offer(
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

        let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) else {
            return;
        };
        let response = TcpPayload::FileResponse {
            transfer_id: transfer_id.clone(),
            sender_id: active.ephemeral_peer_id.clone(),
            accepted,
            timestamp: current_unix_timestamp(),
        };
        let peer_addr = offer.peer_addr;
        active.outbound_tasks.spawn(async move {
            let _ = send_tcp_control_frame(peer_addr, &msg_key, &response).await;
        });

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

    fn handle_cancel_file_transfer(&mut self, transfer_id: &str) {
        let Some(active) = &mut self.active else {
            return;
        };
        if let Some(tr) = active.outbound_transfers.remove(transfer_id) {
            tr.cancel_token.cancel();
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
            let filename = tr.filename.clone();
            drop(tr);
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
    fn handle_inbound_file_offer(
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
                if allow_anomaly_for(active, peer_ip) {
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

        // 画面ロック中等は自動拒否してUIモーダルを出さない
        if self.state != AppStateKind::LoggedIn {
            if let Ok(msg_key) = active.keys.with_msg_key(|k| Zeroizing::new(*k)) {
                let response = TcpPayload::FileResponse {
                    transfer_id: transfer_id.to_string(),
                    sender_id: active.ephemeral_peer_id.clone(),
                    accepted: false,
                    timestamp: current_unix_timestamp(),
                };
                active.outbound_tasks.spawn(async move {
                    let _ = send_tcp_control_frame(peer_addr, &msg_key, &response).await;
                });
            }
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

    #[allow(clippy::too_many_arguments)]
    fn handle_inbound_file_response(
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
            if allow_anomaly_for(active, peer_ip) {
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

    fn handle_inbound_file_chunk(&mut self, chunk: InboundTcpFileChunk) {
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

    fn handle_inbound_file_stream_closed(&mut self, transfer_id: &str) {
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

    fn finish_outbound_transfer_with_error(&mut self, transfer_id: &str, message: String) {
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

    fn handle_file_stream_send_finished(&mut self, transfer_id: &str, result: Result<(), String>) {
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

    async fn perform_logout_or_shutdown(&mut self, shutdown: bool) {
        if let Some(mut active) = self.active.take() {
            self.set_state(AppStateKind::LoggingOut);

            // 1. 暗号化 Bye 2回送信（50ms 間隔）
            if let Some(target) = active.udp_target
                && let Ok(beacon_key) = active.keys.with_beacon_key(|k| Zeroizing::new(*k))
            {
                let start_seq = active.next_udp_seq();
                let _ = active.next_udp_seq();
                let advertised_ip = active.advertised_ip_for_target(Some(target.ip()));
                let _ = send_encrypted_bye_twice(
                    &active.udp_socket,
                    target,
                    &beacon_key,
                    &active.ephemeral_peer_id,
                    start_seq,
                    advertised_ip,
                )
                .await;
            }

            // 2. 全バックグラウンドタスク・送信中タスクへキャンセル指示＆終了待機
            active.cancel.cancel();
            for handle in active.worker_handles.drain(..) {
                let _ = handle.await;
            }
            while active.outbound_tasks.join_next().await.is_some() {}

            // 3. 会話ログ・ピア一覧・リプレイキャッシュ・セッション鍵・識別子を完全 zeroize
            {
                let mut log_guard = self
                    .shared_log
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = log_guard.clear_all();
            }
            active.wipe_in_memory();
            drop(active);

            // 4. 一時領域削除
            let _ = wipe_cache_dir(&self.options.paths);
        } else {
            let _ = wipe_cache_dir(&self.options.paths);
        }

        if shutdown {
            self.set_state(AppStateKind::Exiting);
            self.emit(AppEvent::ShutdownReady);
        } else {
            self.set_state(AppStateKind::LoggedOut);
            self.emit(AppEvent::LogoutCompleted);
        }
    }
}
