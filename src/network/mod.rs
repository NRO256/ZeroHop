pub mod nic;
pub mod rate_limit;
pub mod tcp_transport;
pub mod udp_discovery;

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::crypto::CryptoError;
use crate::domain::protocol::ProtocolError;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("ネットワークI/Oエラー: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("通信がタイムアウトしました")]
    Timeout,
    #[error("利用可能なポートを確保できませんでした")]
    NoAvailablePort,
    #[error("無効な通信先アドレスです: {0}")]
    InvalidEndpoint(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyEvent {
    KeyMismatch {
        peer_ip: IpAddr,
    },
    ClockSkew {
        peer_ip: IpAddr,
        skew_seconds: i64,
    },
    ProtocolVersionMismatch {
        peer_ip: IpAddr,
        received_version: u16,
    },
}

pub fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(i64::MAX as u64) as i64)
}
