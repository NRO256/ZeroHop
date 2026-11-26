mod discovery;
mod messaging;
mod transfer;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use crate::crypto::replay::{DEFAULT_TIMESTAMP_WINDOW_SECS, ReplayCache};
use crate::domain::model::{
    InMemoryChatMessage, MAX_UDP_PACKET_BYTES, PeerRegistry, ThreadKey, UserStatus,
};
use crate::domain::session_log::{SearchHit, SessionLog};
use crate::domain::validation::{validate_and_normalize_display_name, validate_password};
use crate::network::AnomalyEvent;
use crate::network::nic::{NicInfo, resolve_active_nic_from_str};
use crate::network::rate_limit::{AnomalyRateLimiter, UdpIpRateLimiter};
use crate::network::tcp_transport::{InboundTcpEvent, bind_tcp_listener, spawn_tcp_listener_task};
use crate::network::udp_discovery::{
    DEFAULT_BEACON_INTERVAL, DEFAULT_NIC_REFRESH_INTERVAL, DEFAULT_PEER_TIMEOUT_SECS,
    bind_udp_socket, normalize_ip, send_encrypted_bye_twice,
};
use crate::storage::cache_wipe::wipe_cache_dir;
use crate::storage::config::{LocalConfig, load_config, save_config};
use crate::storage::paths::AppPaths;

use discovery::PeerSeqTracker;
use transfer::{ActiveInboundTransfer, OutboundTransferState, PendingInboundOffer};

const HELLO_REPLY_COOLDOWN: Duration = Duration::from_secs(5);
const PEER_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const COMMAND_CHANNEL_CAPACITY: usize = 128;
const INTERNAL_CHANNEL_CAPACITY: usize = 256;
const PEER_SEQ_TTL_SECS: i64 = DEFAULT_TIMESTAMP_WINDOW_SECS * 2;

pub enum TryReadMessage<R> {
    Hit(R),
    Empty,
    Contended,
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

    pub fn try_with_message<R>(
        &self,
        thread: &ThreadKey,
        index: usize,
        f: impl FnOnce(&InMemoryChatMessage) -> R,
    ) -> TryReadMessage<R> {
        let Ok(guard) = self.inner.try_read() else {
            return TryReadMessage::Contended;
        };
        match guard.get_message(thread, index) {
            Some(msg) => TryReadMessage::Hit(f(msg)),
            None => TryReadMessage::Empty,
        }
    }

    pub fn total_bytes(&self) -> usize {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.current_total_bytes()
    }

    pub fn export_thread_messages(&self, thread: &ThreadKey) -> Vec<InMemoryChatMessage> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.export_thread_messages(thread)
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
            UiCommand::SendChat {
                thread,
                body,
                reply_to,
            } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_send_chat(thread, body, reply_to, internal_tx);
                }
                false
            }
            UiCommand::RetryChat { thread, message_id } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_retry_chat(thread, message_id, internal_tx);
                }
                false
            }
            UiCommand::DeleteMessage { thread, message_id } => {
                if self.state == AppStateKind::LoggedIn {
                    self.handle_delete_message(thread, message_id);
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
