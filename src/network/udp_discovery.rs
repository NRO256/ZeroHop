use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::crypto::replay::{DEFAULT_TIMESTAMP_WINDOW_SECS, check_timestamp_window};
use crate::domain::model::UserStatus;
use crate::domain::protocol::{ProtocolError, UdpPayload, decode_udp_frame, encode_udp_frame};
use crate::domain::validation::{validate_and_normalize_display_name, validate_port};
use crate::network::rate_limit::{AnomalyRateLimiter, UdpIpRateLimiter};
use crate::network::{AnomalyEvent, NetworkError, current_unix_timestamp};

pub const DEFAULT_BEACON_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_PEER_TIMEOUT_SECS: i64 = 15;
pub const BYE_REPEAT_COUNT: usize = 2;
pub const BYE_REPEAT_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_NIC_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpProcessOutcome {
    Beacon {
        peer_ip: IpAddr,
        peer_id: String,
        display_name: String,
        tcp_port: u16,
        status: UserStatus,
        timestamp: i64,
    },
    Bye {
        peer_ip: IpAddr,
        peer_id: String,
        timestamp: i64,
    },
    Anomaly(AnomalyEvent),
    Ignored,
}

#[allow(clippy::too_many_arguments)]
pub fn process_udp_datagram(
    beacon_key: &[u8; 32],
    self_peer_id: &str,
    src_ip: IpAddr,
    datagram: &[u8],
    now_inst: Instant,
    now_unix: i64,
    ip_limiter: &mut UdpIpRateLimiter,
    anomaly_limiter: &mut AnomalyRateLimiter,
) -> UdpProcessOutcome {
    if !ip_limiter.allow_at(src_ip, now_inst) {
        return UdpProcessOutcome::Ignored;
    }

    let payload = match decode_udp_frame(beacon_key, datagram) {
        Ok(p) => p,
        Err(ProtocolError::VersionMismatch { received_version }) => {
            if anomaly_limiter.allow_at(src_ip, now_inst) {
                return UdpProcessOutcome::Anomaly(AnomalyEvent::ProtocolVersionMismatch {
                    peer_ip: src_ip,
                    received_version,
                });
            }
            return UdpProcessOutcome::Ignored;
        }
        Err(ProtocolError::DecryptionFailed) => {
            if anomaly_limiter.allow_at(src_ip, now_inst) {
                return UdpProcessOutcome::Anomaly(AnomalyEvent::KeyMismatch { peer_ip: src_ip });
            }
            return UdpProcessOutcome::Ignored;
        }
        Err(_) => return UdpProcessOutcome::Ignored,
    };

    match payload {
        UdpPayload::Beacon {
            ref peer_id,
            ref display_name,
            tcp_port,
            status,
            timestamp,
        } => {
            if peer_id == self_peer_id || peer_id.trim().is_empty() {
                return UdpProcessOutcome::Ignored;
            }
            if let Err(skew_seconds) =
                check_timestamp_window(timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
            {
                if anomaly_limiter.allow_at(src_ip, now_inst) {
                    return UdpProcessOutcome::Anomaly(AnomalyEvent::ClockSkew {
                        peer_ip: src_ip,
                        skew_seconds,
                    });
                }
                return UdpProcessOutcome::Ignored;
            }
            let Ok(clean_name) = validate_and_normalize_display_name(display_name) else {
                return UdpProcessOutcome::Ignored;
            };
            if validate_port(tcp_port).is_err() {
                return UdpProcessOutcome::Ignored;
            }
            UdpProcessOutcome::Beacon {
                peer_ip: src_ip,
                peer_id: peer_id.clone(),
                display_name: clean_name,
                tcp_port,
                status,
                timestamp,
            }
        }
        UdpPayload::Bye {
            ref peer_id,
            timestamp,
        } => {
            if peer_id == self_peer_id || peer_id.trim().is_empty() {
                return UdpProcessOutcome::Ignored;
            }
            if let Err(skew_seconds) =
                check_timestamp_window(timestamp, now_unix, DEFAULT_TIMESTAMP_WINDOW_SECS)
            {
                if anomaly_limiter.allow_at(src_ip, now_inst) {
                    return UdpProcessOutcome::Anomaly(AnomalyEvent::ClockSkew {
                        peer_ip: src_ip,
                        skew_seconds,
                    });
                }
                return UdpProcessOutcome::Ignored;
            }
            UdpProcessOutcome::Bye {
                peer_ip: src_ip,
                peer_id: peer_id.clone(),
                timestamp,
            }
        }
    }
}

fn try_bind_udp_once(addr: SocketAddr, enable_broadcast: bool) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.set_broadcast(enable_broadcast)?;
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_sock)
}

pub fn bind_udp_socket(
    bind_addr: SocketAddr,
    enable_broadcast: bool,
) -> Result<(Arc<UdpSocket>, u16), NetworkError> {
    let sock = match try_bind_udp_once(bind_addr, enable_broadcast) {
        Ok(s) => s,
        Err(_) if bind_addr.port() != 0 => {
            let fallback = SocketAddr::new(bind_addr.ip(), 0);
            try_bind_udp_once(fallback, enable_broadcast)?
        }
        Err(err) => return Err(NetworkError::Io(err)),
    };
    let port = sock.local_addr()?.port();
    Ok((Arc::new(sock), port))
}

pub async fn send_encrypted_beacon(
    socket: &UdpSocket,
    target: SocketAddr,
    beacon_key: &[u8; 32],
    payload: &UdpPayload,
) -> Result<(), NetworkError> {
    let frame = encode_udp_frame(beacon_key, payload)?;
    socket.send_to(&frame, target).await?;
    Ok(())
}

pub async fn send_encrypted_bye_twice(
    socket: &UdpSocket,
    target: SocketAddr,
    beacon_key: &[u8; 32],
    peer_id: &str,
) -> Result<(), NetworkError> {
    for idx in 0..BYE_REPEAT_COUNT {
        let payload = UdpPayload::Bye {
            peer_id: peer_id.to_string(),
            timestamp: current_unix_timestamp(),
        };
        let frame = encode_udp_frame(beacon_key, &payload)?;
        socket.send_to(&frame, target).await?;
        if idx + 1 < BYE_REPEAT_COUNT {
            tokio::time::sleep(BYE_REPEAT_INTERVAL).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn process_udp_accepts_valid_beacon_and_bye_and_rejects_unauthenticated() {
        let room_key = [0x11u8; 32];
        let other_key = [0x99u8; 32];
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 50));
        let now = 1_700_000_000i64;
        let inst = Instant::now();
        let mut ip_lim = UdpIpRateLimiter::default_udp();
        let mut anom_lim = AnomalyRateLimiter::default_anomaly();

        // 正常 Beacon
        let beacon = UdpPayload::Beacon {
            peer_id: "peer-other".to_string(),
            display_name: "鈴木".to_string(),
            tcp_port: 45101,
            status: UserStatus::Online,
            timestamp: now,
        };
        let frame = encode_udp_frame(&room_key, &beacon).unwrap();
        let outcome = process_udp_datagram(
            &room_key,
            "peer-self",
            src_ip,
            &frame,
            inst,
            now,
            &mut ip_lim,
            &mut anom_lim,
        );
        assert_eq!(
            outcome,
            UdpProcessOutcome::Beacon {
                peer_ip: src_ip,
                peer_id: "peer-other".to_string(),
                display_name: "鈴木".to_string(),
                tcp_port: 45101,
                status: UserStatus::Online,
                timestamp: now,
            }
        );

        // 自身エコーは無視
        let self_beacon = UdpPayload::Beacon {
            peer_id: "peer-self".to_string(),
            display_name: "自分".to_string(),
            tcp_port: 45101,
            status: UserStatus::Online,
            timestamp: now,
        };
        let self_frame = encode_udp_frame(&room_key, &self_beacon).unwrap();
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "peer-self",
                src_ip,
                &self_frame,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Ignored
        );

        // 別ルーム偽 Bye は KeyMismatch（レート制限付き）として破棄
        let fake_bye = UdpPayload::Bye {
            peer_id: "peer-other".to_string(),
            timestamp: now,
        };
        let fake_bye_frame = encode_udp_frame(&other_key, &fake_bye).unwrap();
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "peer-self",
                src_ip,
                &fake_bye_frame,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Anomaly(AnomalyEvent::KeyMismatch { peer_ip: src_ip })
        );
        // 同一 IP 60秒内2回目の異常通知は Ignored
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "peer-self",
                src_ip,
                &fake_bye_frame,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Ignored
        );

        // 別 IP からの時計ズレ（+400秒）とバージョン不一致（v3）
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 51));
        let skewed = UdpPayload::Bye {
            peer_id: "peer-other".to_string(),
            timestamp: now + 400,
        };
        let skewed_frame = encode_udp_frame(&room_key, &skewed).unwrap();
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "peer-self",
                ip2,
                &skewed_frame,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Anomaly(AnomalyEvent::ClockSkew {
                peer_ip: ip2,
                skew_seconds: 400,
            })
        );

        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 52));
        let mut wrong_ver = frame.clone();
        wrong_ver[5] = 3;
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "peer-self",
                ip3,
                &wrong_ver,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Anomaly(AnomalyEvent::ProtocolVersionMismatch {
                peer_ip: ip3,
                received_version: 3,
            })
        );
    }

    #[test]
    fn udp_rate_limit_drops_flood_above_10_per_sec() {
        let room_key = [0x33u8; 32];
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 88));
        let inst = Instant::now();
        let now = 1_700_000_000i64;
        let mut ip_lim = UdpIpRateLimiter::default_udp();
        let mut anom_lim = AnomalyRateLimiter::default_anomaly();

        let bye = UdpPayload::Bye {
            peer_id: "peer-x".to_string(),
            timestamp: now,
        };
        let frame = encode_udp_frame(&room_key, &bye).unwrap();

        for _ in 0..10 {
            assert!(matches!(
                process_udp_datagram(
                    &room_key,
                    "self",
                    src_ip,
                    &frame,
                    inst,
                    now,
                    &mut ip_lim,
                    &mut anom_lim,
                ),
                UdpProcessOutcome::Bye { .. }
            ));
        }

        // 11件目は復号前にレート制限で Ignored
        assert_eq!(
            process_udp_datagram(
                &room_key,
                "self",
                src_ip,
                &frame,
                inst,
                now,
                &mut ip_lim,
                &mut anom_lim,
            ),
            UdpProcessOutcome::Ignored
        );
    }
}
