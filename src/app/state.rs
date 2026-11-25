use std::fmt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::domain::model::{PeerView, ThreadKey, UserStatus};
use crate::network::nic::NicInfo;
use crate::storage::config::LocalConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStateKind {
    LoggedOut,
    Authenticating,
    LoggedIn,
    Locked,
    LoggingOut,
    Exiting,
}

pub fn can_transition(from: AppStateKind, to: AppStateKind) -> bool {
    if from == to {
        return false;
    }
    matches!(
        (from, to),
        (
            AppStateKind::LoggedOut,
            AppStateKind::Authenticating | AppStateKind::Exiting
        ) | (
            AppStateKind::Authenticating,
            AppStateKind::LoggedOut
                | AppStateKind::LoggedIn
                | AppStateKind::LoggingOut
                | AppStateKind::Exiting
        ) | (
            AppStateKind::LoggedIn,
            AppStateKind::Locked | AppStateKind::LoggingOut
        ) | (
            AppStateKind::Locked,
            AppStateKind::LoggedIn | AppStateKind::LoggingOut
        ) | (
            AppStateKind::LoggingOut,
            AppStateKind::LoggedOut | AppStateKind::Exiting
        )
    )
}

pub enum UiCommand {
    LoginRequest {
        display_name: String,
        password: Zeroizing<String>,
    },
    CancelLogin,
    SendChat {
        thread: ThreadKey,
        body: Zeroizing<String>,
    },
    RetryChat {
        thread: ThreadKey,
        message_id: String,
    },
    AddManualPeer {
        host: String,
        tcp_port: u16,
    },
    RefreshNetwork,
    ChangeStatus(UserStatus),
    ClearSessionChat {
        thread: Option<ThreadKey>,
    },
    SendFile {
        peer_id: String,
        file_path: PathBuf,
    },
    RespondFileOffer {
        transfer_id: String,
        accept: bool,
        save_path: Option<PathBuf>,
    },
    CancelFileTransfer {
        transfer_id: String,
    },
    UpdateConfig(LocalConfig),
    LockScreen,
    UnlockScreen {
        password: Zeroizing<String>,
    },
    Logout,
    Shutdown,
}

impl fmt::Debug for UiCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoginRequest { display_name, .. } => f
                .debug_struct("LoginRequest")
                .field("display_name", display_name)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::CancelLogin => f.write_str("CancelLogin"),
            Self::SendChat { thread, body } => f
                .debug_struct("SendChat")
                .field("thread", thread)
                .field("body_len", &body.len())
                .finish(),
            Self::RetryChat { thread, message_id } => f
                .debug_struct("RetryChat")
                .field("thread", thread)
                .field("message_id", message_id)
                .finish(),
            Self::AddManualPeer { host, tcp_port } => f
                .debug_struct("AddManualPeer")
                .field("host", host)
                .field("tcp_port", tcp_port)
                .finish(),
            Self::RefreshNetwork => f.write_str("RefreshNetwork"),
            Self::ChangeStatus(st) => f.debug_tuple("ChangeStatus").field(st).finish(),
            Self::ClearSessionChat { thread } => f
                .debug_struct("ClearSessionChat")
                .field("thread", thread)
                .finish(),
            Self::SendFile { peer_id, file_path } => f
                .debug_struct("SendFile")
                .field("peer_id", peer_id)
                .field("file_path", file_path)
                .finish(),
            Self::RespondFileOffer {
                transfer_id,
                accept,
                ..
            } => f
                .debug_struct("RespondFileOffer")
                .field("transfer_id", transfer_id)
                .field("accept", accept)
                .finish(),
            Self::CancelFileTransfer { transfer_id } => f
                .debug_struct("CancelFileTransfer")
                .field("transfer_id", transfer_id)
                .finish(),
            Self::UpdateConfig(cfg) => f.debug_tuple("UpdateConfig").field(cfg).finish(),
            Self::LockScreen => f.write_str("LockScreen"),
            Self::UnlockScreen { .. } => f
                .debug_struct("UnlockScreen")
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Logout => f.write_str("Logout"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    LoginSucceeded {
        display_name: String,
        room_code: String,
        ephemeral_peer_id: String,
        tcp_port: u16,
        udp_port: u16,
        nic_info: Option<NicInfo>,
    },
    LoginFailed {
        reason: String,
    },
    PeerListChanged(Vec<PeerView>),
    PeerJoined {
        peer_id: String,
        display_name: String,
    },
    PeerLeft {
        peer_id: String,
        display_name: String,
    },
    ThreadUpdated {
        thread: ThreadKey,
        new_count: usize,
        total_log_bytes: usize,
    },
    IncomingMessageReceived {
        thread: ThreadKey,
        sender_name: String,
        preview: String,
    },
    ScreenLocked,
    ScreenUnlockResult {
        ok: bool,
    },
    DeliveryUpdated {
        thread: ThreadKey,
        message_id: String,
    },
    FileOfferReceived {
        transfer_id: String,
        peer_id: String,
        peer_name: String,
        filename: String,
        file_size: u64,
        sha256_hex: String,
    },
    FileTransferProgress {
        transfer_id: String,
        peer_id: String,
        filename: String,
        is_sending: bool,
        transferred_bytes: u64,
        total_bytes: u64,
    },
    FileTransferFinished {
        transfer_id: String,
        peer_id: String,
        filename: String,
        is_sending: bool,
        ok: bool,
        message: String,
    },
    NetworkRefreshed {
        nic_info: Option<NicInfo>,
        tcp_port: u16,
        udp_port: u16,
    },
    StatusChanged(UserStatus),
    KeyMismatchDetected {
        peer_ip: std::net::IpAddr,
    },
    ClockSkewDetected {
        peer_ip: std::net::IpAddr,
        skew_seconds: i64,
    },
    ProtocolVersionMismatch {
        peer_ip: std::net::IpAddr,
        received_version: u16,
    },
    AdvertisedIpMismatch {
        peer_ip: std::net::IpAddr,
        advertised_ip: std::net::IpAddr,
    },
    LogoutCompleted,
    ShutdownReady,
    ErrorNotice(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transition_table_enforces_fail_closed_lifecycle() {
        assert!(can_transition(
            AppStateKind::LoggedOut,
            AppStateKind::Authenticating
        ));
        assert!(can_transition(
            AppStateKind::LoggedOut,
            AppStateKind::Exiting
        ));
        assert!(!can_transition(
            AppStateKind::LoggedOut,
            AppStateKind::LoggedIn
        ));
        assert!(!can_transition(
            AppStateKind::LoggedIn,
            AppStateKind::LoggedOut
        ));
        assert!(can_transition(AppStateKind::LoggedIn, AppStateKind::Locked));
        assert!(can_transition(AppStateKind::Locked, AppStateKind::LoggedIn));
        assert!(can_transition(
            AppStateKind::Locked,
            AppStateKind::LoggingOut
        ));
        assert!(!can_transition(
            AppStateKind::Locked,
            AppStateKind::LoggedOut
        ));
        assert!(can_transition(
            AppStateKind::LoggedIn,
            AppStateKind::LoggingOut
        ));
        assert!(can_transition(
            AppStateKind::LoggingOut,
            AppStateKind::LoggedOut
        ));
        assert!(can_transition(
            AppStateKind::LoggingOut,
            AppStateKind::Exiting
        ));
    }
}
