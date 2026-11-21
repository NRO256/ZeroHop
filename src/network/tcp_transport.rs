use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::domain::protocol::{
    FrameKind, ProtocolError, TCP_PREAMBLE_LEN, TcpPayload, decode_tcp_control_body,
    encode_tcp_control_frame, validate_tcp_frame_preamble,
};
use crate::network::rate_limit::AnomalyRateLimiter;
use crate::network::{AnomalyEvent, NetworkError};

pub const TCP_FALLBACK_PORT_START: u16 = 45101;
pub const TCP_FALLBACK_PORT_END: u16 = 45120;
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const TCP_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_CONCURRENT_INCOMING_TCP: usize = 64;
pub const MAX_CONCURRENT_BROADCAST_SENDS: usize = 16;

#[derive(Debug, Error)]
pub enum TcpReadError {
    #[error("I/Oエラー: {0}")]
    Io(#[from] std::io::Error),
    #[error("読み取りがタイムアウトしました")]
    Timeout,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("未対応のフレーム種別です: 0x{0:02x}")]
    UnsupportedKind(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTcpMessage {
    pub peer_ip: IpAddr,
    pub payload: TcpPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundTcpEvent {
    Payload(InboundTcpMessage),
    Anomaly(AnomalyEvent),
}

pub async fn bind_tcp_listener(
    bind_ip: IpAddr,
    preferred_port: u16,
) -> Result<(TcpListener, u16), NetworkError> {
    if preferred_port == 0 {
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0)).await?;
        let port = listener.local_addr()?.port();
        return Ok((listener, port));
    }

    if let Ok(listener) = TcpListener::bind(SocketAddr::new(bind_ip, preferred_port)).await {
        let port = listener.local_addr()?.port();
        return Ok((listener, port));
    }

    for port in TCP_FALLBACK_PORT_START..=TCP_FALLBACK_PORT_END {
        if port == preferred_port {
            continue;
        }
        if let Ok(listener) = TcpListener::bind(SocketAddr::new(bind_ip, port)).await {
            let bound_port = listener.local_addr()?.port();
            return Ok((listener, bound_port));
        }
    }

    let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))
        .await
        .map_err(|_| NetworkError::NoAvailablePort)?;
    let bound_port = listener.local_addr()?.port();
    Ok((listener, bound_port))
}

pub async fn send_tcp_control_frame(
    target: SocketAddr,
    msg_key: &[u8; 32],
    payload: &TcpPayload,
) -> Result<(), NetworkError> {
    send_tcp_control_frame_with_timeout(target, msg_key, payload, TCP_CONNECT_TIMEOUT).await
}

pub async fn send_tcp_control_frame_with_timeout(
    target: SocketAddr,
    msg_key: &[u8; 32],
    payload: &TcpPayload,
    connect_timeout: Duration,
) -> Result<(), NetworkError> {
    let frame = encode_tcp_control_frame(msg_key, payload)?;
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(target))
        .await
        .map_err(|_| NetworkError::Timeout)??;
    let _ = stream.set_nodelay(true);

    tokio::time::timeout(TCP_WRITE_TIMEOUT, async {
        stream.write_all(&frame).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| NetworkError::Timeout)??;
    Ok(())
}

pub async fn send_broadcast_control(
    targets: Vec<(String, SocketAddr)>,
    msg_key: Zeroizing<[u8; 32]>,
    payload: TcpPayload,
) -> Vec<(String, Result<(), NetworkError>)> {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_BROADCAST_SENDS));
    let mut join_set = JoinSet::new();

    for (peer_id, target_addr) in targets {
        let sem = Arc::clone(&semaphore);
        let key_copy = Zeroizing::new(*msg_key);
        let payload_copy = payload.clone();
        join_set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (
                    peer_id,
                    Err(NetworkError::InvalidEndpoint(
                        "送信セマフォがクローズされました".to_string(),
                    )),
                );
            };
            let res = send_tcp_control_frame(target_addr, &key_copy, &payload_copy).await;
            (peer_id, res)
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        if let Ok(item) = joined {
            results.push(item);
        }
    }
    results
}

pub async fn read_tcp_control_frame(
    stream: &mut TcpStream,
    msg_key: &[u8; 32],
) -> Result<TcpPayload, TcpReadError> {
    let mut preamble = [0u8; TCP_PREAMBLE_LEN];
    tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut preamble))
        .await
        .map_err(|_| TcpReadError::Timeout)??;

    // バッファ確保前にバージョン・種別・予約バイト・サイズ上限を検査
    let header = validate_tcp_frame_preamble(&preamble)?;
    if header.frame_kind != FrameKind::ControlJson {
        return Err(TcpReadError::UnsupportedKind(header.frame_kind as u8));
    }

    let mut remaining = vec![0u8; header.remaining_len];
    tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut remaining))
        .await
        .map_err(|_| TcpReadError::Timeout)??;

    decode_tcp_control_body(msg_key, &header, &remaining).map_err(TcpReadError::Protocol)
}

async fn handle_incoming_connection(
    mut stream: TcpStream,
    peer_ip: IpAddr,
    msg_key: Zeroizing<[u8; 32]>,
    tx: mpsc::Sender<InboundTcpEvent>,
    anomaly_limiter: Arc<Mutex<AnomalyRateLimiter>>,
) {
    match read_tcp_control_frame(&mut stream, &msg_key).await {
        Ok(payload) => {
            let _ = tx
                .send(InboundTcpEvent::Payload(InboundTcpMessage {
                    peer_ip,
                    payload,
                }))
                .await;
        }
        Err(TcpReadError::Protocol(ProtocolError::VersionMismatch { received_version })) => {
            let allowed = {
                let mut guard = anomaly_limiter.lock().await;
                guard.allow_at(peer_ip, Instant::now())
            };
            if allowed {
                let _ = tx
                    .send(InboundTcpEvent::Anomaly(
                        AnomalyEvent::ProtocolVersionMismatch {
                            peer_ip,
                            received_version,
                        },
                    ))
                    .await;
            }
        }
        Err(TcpReadError::Protocol(ProtocolError::DecryptionFailed)) => {
            let allowed = {
                let mut guard = anomaly_limiter.lock().await;
                guard.allow_at(peer_ip, Instant::now())
            };
            if allowed {
                let _ = tx
                    .send(InboundTcpEvent::Anomaly(AnomalyEvent::KeyMismatch {
                        peer_ip,
                    }))
                    .await;
            }
        }
        Err(_) => {}
    }
}

pub fn spawn_tcp_listener_task(
    listener: TcpListener,
    msg_key: Zeroizing<[u8; 32]>,
    tx: mpsc::Sender<InboundTcpEvent>,
    anomaly_limiter: Arc<Mutex<AnomalyRateLimiter>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_INCOMING_TCP));
        let mut conn_tasks = JoinSet::new();

        loop {
            while let Some(joined) = conn_tasks.try_join_next() {
                let _ = joined;
            }

            tokio::select! {
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, remote_addr)) = accepted else {
                        break;
                    };
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        drop(stream);
                        continue;
                    };
                    let key_copy = Zeroizing::new(*msg_key);
                    let tx_clone = tx.clone();
                    let limiter_clone = Arc::clone(&anomaly_limiter);
                    let conn_cancel = cancel.clone();
                    conn_tasks.spawn(async move {
                        let _permit = permit;
                        tokio::select! {
                            _ = conn_cancel.cancelled() => {},
                            _ = handle_incoming_connection(
                                stream,
                                remote_addr.ip(),
                                key_copy,
                                tx_clone,
                                limiter_clone,
                            ) => {},
                        }
                    });
                }
            }
        }

        while conn_tasks.join_next().await.is_some() {}
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::domain::model::{MAX_TCP_CONTROL_FRAME_BYTES, UserStatus};

    use super::*;

    #[tokio::test]
    async fn tcp_listener_fallbacks_when_port_is_occupied() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (first, port1) = bind_tcp_listener(ip, 0).await.unwrap();
        let (second, port2) = bind_tcp_listener(ip, port1).await.unwrap();
        assert_ne!(port1, port2);
        drop(first);
        drop(second);
    }

    #[tokio::test]
    async fn tcp_listener_rejects_oversized_preamble_and_reports_anomalies() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (listener, port) = bind_tcp_listener(ip, 0).await.unwrap();
        let target = SocketAddr::new(ip, port);

        let key = Zeroizing::new([0x44u8; 32]);
        let wrong_key = Zeroizing::new([0x88u8; 32]);
        let (tx, mut rx) = mpsc::channel(16);
        let limiter = Arc::new(Mutex::new(AnomalyRateLimiter::default_anomaly()));
        let cancel = CancellationToken::new();

        let handle = spawn_tcp_listener_task(listener, key.clone(), tx, limiter, cancel.clone());

        // 1. 16 KiB 超え preamble 送信 -> サーバー側がパニック/大容量確保せず即時切断
        let mut raw_stream = TcpStream::connect(target).await.unwrap();
        let mut oversized_pre = [0u8; 8];
        oversized_pre[0..4]
            .copy_from_slice(&((MAX_TCP_CONTROL_FRAME_BYTES as u32) + 100).to_be_bytes());
        oversized_pre[4..6].copy_from_slice(&4u16.to_be_bytes());
        oversized_pre[6] = FrameKind::ControlJson as u8;
        oversized_pre[7] = 0;
        raw_stream.write_all(&oversized_pre).await.unwrap();
        drop(raw_stream);

        // 2. 別鍵暗号化フレーム -> KeyMismatch 通知
        let hello = TcpPayload::Hello {
            sender_id: "intruder".to_string(),
            sender_name: "Intruder".to_string(),
            tcp_port: 45101,
            status: UserStatus::Online,
            timestamp: 1_700_000_000,
        };
        send_tcp_control_frame(target, &wrong_key, &hello)
            .await
            .unwrap();

        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ev,
            InboundTcpEvent::Anomaly(AnomalyEvent::KeyMismatch { peer_ip: ip })
        );

        // 3. 正常鍵フレーム -> Payload 通知
        send_tcp_control_frame(target, &key, &hello).await.unwrap();
        let ev_ok = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            ev_ok,
            InboundTcpEvent::Payload(InboundTcpMessage {
                peer_ip: ip,
                payload: hello,
            })
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_control_respects_semaphore_across_many_targets() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let key = Zeroizing::new([0x55u8; 32]);
        let cancel = CancellationToken::new();
        let limiter = Arc::new(Mutex::new(AnomalyRateLimiter::default_anomaly()));
        let (tx, mut rx) = mpsc::channel(32);

        let mut targets = Vec::new();
        let mut handles = Vec::new();
        for idx in 0..20 {
            let (listener, port) = bind_tcp_listener(ip, 0).await.unwrap();
            targets.push((format!("peer-{idx}"), SocketAddr::new(ip, port)));
            handles.push(spawn_tcp_listener_task(
                listener,
                key.clone(),
                tx.clone(),
                Arc::clone(&limiter),
                cancel.clone(),
            ));
        }
        drop(tx);

        let chat = TcpPayload::Chat {
            message_id: "bc-all".to_string(),
            sender_id: "sender".to_string(),
            sender_name: "Sender".to_string(),
            is_broadcast: true,
            body: "セマフォ20並列送信テスト".to_string(),
            timestamp: 1_700_000_000,
        };
        let results = send_broadcast_control(targets, key, chat).await;
        assert_eq!(results.len(), 20);
        assert!(results.iter().all(|(_, res)| res.is_ok()));

        let mut received = 0usize;
        while tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            received += 1;
            if received == 20 {
                break;
            }
        }
        assert_eq!(received, 20);

        cancel.cancel();
        for h in handles {
            h.await.unwrap();
        }
    }
}
