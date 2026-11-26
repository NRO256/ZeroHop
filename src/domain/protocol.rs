use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::aead::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, decrypt_aead, encrypt_aead, generate_nonce,
};
use crate::domain::model::{
    CURRENT_PROTOCOL_VERSION, MAX_TCP_CONTROL_FRAME_BYTES, MAX_TCP_FILE_CHUNK_FRAME_BYTES,
    MAX_UDP_PACKET_BYTES, UDP_MAGIC, UserStatus,
};

pub const UDP_HEADER_LEN: usize = 6; // magic (4B) + version (2B)
pub const TCP_PREAMBLE_LEN: usize = 8; // body_len (4B) + version (2B) + kind (1B) + reserved (1B)
pub const TCP_AAD_LEN: usize = 4; // version (2B) + kind (1B) + reserved (1B)
pub const MAX_FILE_CHUNK_RAW_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    ControlJson = 0x01,
    FileChunk = 0x02,
}

impl FrameKind {
    pub fn from_byte(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(Self::ControlJson),
            0x02 => Ok(Self::FileChunk),
            other => Err(ProtocolError::UnsupportedFrameKind(other)),
        }
    }

    pub fn max_body_bytes(self) -> usize {
        match self {
            Self::ControlJson => MAX_TCP_CONTROL_FRAME_BYTES,
            Self::FileChunk => MAX_TCP_FILE_CHUNK_FRAME_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFrameHeader {
    pub body_len: usize,
    pub protocol_version: u16,
    pub frame_kind: FrameKind,
    pub reserved: u8,
    pub remaining_len: usize,
}

impl TcpFrameHeader {
    pub fn aad_bytes(&self) -> [u8; TCP_AAD_LEN] {
        let ver = self.protocol_version.to_be_bytes();
        [ver[0], ver[1], self.frame_kind as u8, self.reserved]
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("マジックバイトが一致しません")]
    InvalidMagic,
    #[error(
        "プロトコルバージョン不一致（受信: v{received_version}, 期待: v{CURRENT_PROTOCOL_VERSION}）"
    )]
    VersionMismatch { received_version: u16 },
    #[error("未対応のフレーム種別です: 0x{0:02x}")]
    UnsupportedFrameKind(u8),
    #[error("予約バイトが不正です: 0x{0:02x}")]
    InvalidReservedByte(u8),
    #[error("フレーム長が最小サイズ未満です（{actual} < {min} バイト）")]
    FrameTooShort { actual: usize, min: usize },
    #[error("フレーム長が上限を超過しました（{actual} > {max} バイト）")]
    FrameTooLarge { actual: usize, max: usize },
    #[error("AEAD復号または認証検証に失敗しました")]
    DecryptionFailed,
    #[error("暗号化処理に失敗しました")]
    EncryptionFailed,
    #[error("ペイロードの形式が不正です: {0}")]
    InvalidPayload(String),
}

/// UDP AEAD 復号後ペイロード（beacon_key で保護）
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind")]
pub enum UdpPayload {
    Beacon {
        peer_id: String,
        display_name: String,
        tcp_port: u16,
        #[zeroize(skip)]
        status: UserStatus,
        timestamp: i64,
        #[serde(default)]
        seq: u64,
        #[zeroize(skip)]
        #[serde(default)]
        advertised_ip: Option<IpAddr>,
    },
    Bye {
        peer_id: String,
        timestamp: i64,
        #[serde(default)]
        seq: u64,
        #[zeroize(skip)]
        #[serde(default)]
        advertised_ip: Option<IpAddr>,
    },
}

/// TCP frame_kind = 0x01 の AEAD 復号後ペイロード（msg_key で保護）
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind")]
pub enum TcpPayload {
    Hello {
        sender_id: String,
        sender_name: String,
        tcp_port: u16,
        #[zeroize(skip)]
        status: UserStatus,
        timestamp: i64,
        #[serde(default)]
        seq: u64,
        #[zeroize(skip)]
        #[serde(default)]
        advertised_ip: Option<IpAddr>,
    },
    Chat {
        message_id: String,
        sender_id: String,
        sender_name: String,
        is_broadcast: bool,
        body: String,
        timestamp: i64,
        #[serde(default)]
        reply_to_id: Option<String>,
        #[serde(default)]
        reply_to_sender: Option<String>,
        #[serde(default)]
        reply_to_preview: Option<String>,
    },
    Ack {
        message_id: String,
        receiver_id: String,
        timestamp: i64,
    },
    FileOffer {
        transfer_id: String,
        sender_id: String,
        filename: String,
        file_size: u64,
        sha256_hex: String,
        timestamp: i64,
    },
    FileResponse {
        transfer_id: String,
        sender_id: String,
        accepted: bool,
        timestamp: i64,
    },
    FileCancel {
        transfer_id: String,
        sender_id: String,
        timestamp: i64,
    },
    DeleteMessage {
        message_id: String,
        sender_id: String,
        is_broadcast: bool,
        timestamp: i64,
    },
}

/// TCP frame_kind = 0x02 の復号後先頭メタヘッダ（直後に生チャンクバイト列）
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FileChunkHeader {
    pub transfer_id: String,
    pub sender_id: String,
    pub chunk_index: u64,
    pub timestamp: i64,
}

fn udp_aad(version: u16) -> [u8; UDP_HEADER_LEN] {
    let ver = version.to_be_bytes();
    [
        UDP_MAGIC[0],
        UDP_MAGIC[1],
        UDP_MAGIC[2],
        UDP_MAGIC[3],
        ver[0],
        ver[1],
    ]
}

fn tcp_aad(version: u16, kind: FrameKind, reserved: u8) -> [u8; TCP_AAD_LEN] {
    let ver = version.to_be_bytes();
    [ver[0], ver[1], kind as u8, reserved]
}

pub fn encode_udp_frame(
    beacon_key: &[u8; 32],
    payload: &UdpPayload,
) -> Result<Vec<u8>, ProtocolError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload).map_err(|e| ProtocolError::InvalidPayload(e.to_string()))?,
    );
    let aad = udp_aad(CURRENT_PROTOCOL_VERSION);
    let nonce = generate_nonce();
    let ciphertext = encrypt_aead(beacon_key, &nonce, &aad, &plaintext)
        .map_err(|_| ProtocolError::EncryptionFailed)?;

    let total_len = UDP_HEADER_LEN + AEAD_NONCE_LEN + ciphertext.len();
    if total_len > MAX_UDP_PACKET_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            actual: total_len,
            max: MAX_UDP_PACKET_BYTES,
        });
    }

    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&aad);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

pub fn decode_udp_frame(
    beacon_key: &[u8; 32],
    datagram: &[u8],
) -> Result<UdpPayload, ProtocolError> {
    if datagram.len() > MAX_UDP_PACKET_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            actual: datagram.len(),
            max: MAX_UDP_PACKET_BYTES,
        });
    }
    if datagram.len() < UDP_HEADER_LEN {
        return Err(ProtocolError::FrameTooShort {
            actual: datagram.len(),
            min: UDP_HEADER_LEN,
        });
    }
    if datagram[0..4] != UDP_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = u16::from_be_bytes([datagram[4], datagram[5]]);
    if version != CURRENT_PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            received_version: version,
        });
    }

    let min_total = UDP_HEADER_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    if datagram.len() < min_total {
        return Err(ProtocolError::FrameTooShort {
            actual: datagram.len(),
            min: min_total,
        });
    }

    let aad = &datagram[0..UDP_HEADER_LEN];
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&datagram[UDP_HEADER_LEN..UDP_HEADER_LEN + AEAD_NONCE_LEN]);
    let ciphertext = &datagram[UDP_HEADER_LEN + AEAD_NONCE_LEN..];

    let plaintext = decrypt_aead(beacon_key, &nonce, aad, ciphertext)
        .map_err(|_| ProtocolError::DecryptionFailed)?;
    serde_json::from_slice(&plaintext).map_err(|e| ProtocolError::InvalidPayload(e.to_string()))
}

/// 受信ソケットから最初の8バイト読込直後・バッファ確保前に呼ぶ事前検査
pub fn validate_tcp_frame_preamble(
    preamble: &[u8; TCP_PREAMBLE_LEN],
) -> Result<TcpFrameHeader, ProtocolError> {
    let body_len =
        u32::from_be_bytes([preamble[0], preamble[1], preamble[2], preamble[3]]) as usize;
    let protocol_version = u16::from_be_bytes([preamble[4], preamble[5]]);
    let frame_kind = FrameKind::from_byte(preamble[6])?;
    let reserved = preamble[7];

    if protocol_version != CURRENT_PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            received_version: protocol_version,
        });
    }
    if reserved != 0 {
        return Err(ProtocolError::InvalidReservedByte(reserved));
    }

    let min_body = TCP_AAD_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN;
    if body_len < min_body {
        return Err(ProtocolError::FrameTooShort {
            actual: body_len,
            min: min_body,
        });
    }
    let max_body = frame_kind.max_body_bytes();
    if body_len > max_body {
        return Err(ProtocolError::FrameTooLarge {
            actual: body_len,
            max: max_body,
        });
    }

    Ok(TcpFrameHeader {
        body_len,
        protocol_version,
        frame_kind,
        reserved,
        remaining_len: body_len - TCP_AAD_LEN,
    })
}

fn build_tcp_frame(
    msg_key: &[u8; 32],
    kind: FrameKind,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let aad = tcp_aad(CURRENT_PROTOCOL_VERSION, kind, 0);
    let nonce = generate_nonce();
    let ciphertext = encrypt_aead(msg_key, &nonce, &aad, plaintext)
        .map_err(|_| ProtocolError::EncryptionFailed)?;

    let body_len = TCP_AAD_LEN + AEAD_NONCE_LEN + ciphertext.len();
    let max_body = kind.max_body_bytes();
    if body_len > max_body {
        return Err(ProtocolError::FrameTooLarge {
            actual: body_len,
            max: max_body,
        });
    }
    let body_len_u32 = u32::try_from(body_len).map_err(|_| ProtocolError::FrameTooLarge {
        actual: body_len,
        max: max_body,
    })?;

    let mut frame = Vec::with_capacity(4 + body_len);
    frame.extend_from_slice(&body_len_u32.to_be_bytes());
    frame.extend_from_slice(&aad);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

pub fn encode_tcp_control_frame(
    msg_key: &[u8; 32],
    payload: &TcpPayload,
) -> Result<Vec<u8>, ProtocolError> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload).map_err(|e| ProtocolError::InvalidPayload(e.to_string()))?,
    );
    build_tcp_frame(msg_key, FrameKind::ControlJson, &plaintext)
}

pub fn decode_tcp_control_body(
    msg_key: &[u8; 32],
    header: &TcpFrameHeader,
    remaining: &[u8],
) -> Result<TcpPayload, ProtocolError> {
    if header.frame_kind != FrameKind::ControlJson {
        return Err(ProtocolError::UnsupportedFrameKind(header.frame_kind as u8));
    }
    if remaining.len() != header.remaining_len || remaining.len() < AEAD_NONCE_LEN + AEAD_TAG_LEN {
        return Err(ProtocolError::FrameTooShort {
            actual: remaining.len(),
            min: header.remaining_len,
        });
    }

    let aad = header.aad_bytes();
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&remaining[..AEAD_NONCE_LEN]);
    let ciphertext = &remaining[AEAD_NONCE_LEN..];

    let plaintext = decrypt_aead(msg_key, &nonce, &aad, ciphertext)
        .map_err(|_| ProtocolError::DecryptionFailed)?;
    serde_json::from_slice(&plaintext).map_err(|e| ProtocolError::InvalidPayload(e.to_string()))
}

pub fn decode_tcp_control_frame(
    msg_key: &[u8; 32],
    frame: &[u8],
) -> Result<TcpPayload, ProtocolError> {
    if frame.len() < TCP_PREAMBLE_LEN {
        return Err(ProtocolError::FrameTooShort {
            actual: frame.len(),
            min: TCP_PREAMBLE_LEN,
        });
    }
    let preamble: [u8; TCP_PREAMBLE_LEN] =
        frame[..TCP_PREAMBLE_LEN]
            .try_into()
            .map_err(|_| ProtocolError::FrameTooShort {
                actual: frame.len(),
                min: TCP_PREAMBLE_LEN,
            })?;
    let header = validate_tcp_frame_preamble(&preamble)?;
    let remaining = &frame[TCP_PREAMBLE_LEN..];
    if remaining.len() != header.remaining_len {
        return Err(ProtocolError::InvalidPayload(
            "フレーム長と実データ長が一致しません".to_string(),
        ));
    }
    decode_tcp_control_body(msg_key, &header, remaining)
}

pub fn encode_tcp_file_chunk_frame(
    msg_key: &[u8; 32],
    header: &FileChunkHeader,
    chunk_bytes: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if chunk_bytes.len() > MAX_FILE_CHUNK_RAW_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            actual: chunk_bytes.len(),
            max: MAX_FILE_CHUNK_RAW_BYTES,
        });
    }
    let header_json = Zeroizing::new(
        serde_json::to_vec(header).map_err(|e| ProtocolError::InvalidPayload(e.to_string()))?,
    );
    let header_len = u16::try_from(header_json.len())
        .map_err(|_| ProtocolError::InvalidPayload("チャンクヘッダが大きすぎます".to_string()))?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        2 + header_json.len() + chunk_bytes.len(),
    ));
    plaintext.extend_from_slice(&header_len.to_be_bytes());
    plaintext.extend_from_slice(&header_json);
    plaintext.extend_from_slice(chunk_bytes);

    build_tcp_frame(msg_key, FrameKind::FileChunk, &plaintext)
}

pub fn decode_tcp_file_chunk_body(
    msg_key: &[u8; 32],
    header: &TcpFrameHeader,
    remaining: &[u8],
) -> Result<(FileChunkHeader, Zeroizing<Vec<u8>>), ProtocolError> {
    if header.frame_kind != FrameKind::FileChunk {
        return Err(ProtocolError::UnsupportedFrameKind(header.frame_kind as u8));
    }
    if remaining.len() != header.remaining_len || remaining.len() < AEAD_NONCE_LEN + AEAD_TAG_LEN {
        return Err(ProtocolError::FrameTooShort {
            actual: remaining.len(),
            min: header.remaining_len,
        });
    }

    let aad = header.aad_bytes();
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&remaining[..AEAD_NONCE_LEN]);
    let ciphertext = &remaining[AEAD_NONCE_LEN..];

    let plaintext = decrypt_aead(msg_key, &nonce, &aad, ciphertext)
        .map_err(|_| ProtocolError::DecryptionFailed)?;
    if plaintext.len() < 2 {
        return Err(ProtocolError::InvalidPayload(
            "チャンクヘッダ長が欠落しています".to_string(),
        ));
    }
    let header_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if 2 + header_len > plaintext.len() {
        return Err(ProtocolError::InvalidPayload(
            "チャンクヘッダ長がデータ境界を超過しています".to_string(),
        ));
    }
    let chunk_header: FileChunkHeader = serde_json::from_slice(&plaintext[2..2 + header_len])
        .map_err(|e| ProtocolError::InvalidPayload(e.to_string()))?;
    let raw_bytes = Zeroizing::new(plaintext[2 + header_len..].to_vec());
    Ok((chunk_header, raw_bytes))
}

pub fn decode_tcp_file_chunk_frame(
    msg_key: &[u8; 32],
    frame: &[u8],
) -> Result<(FileChunkHeader, Zeroizing<Vec<u8>>), ProtocolError> {
    if frame.len() < TCP_PREAMBLE_LEN {
        return Err(ProtocolError::FrameTooShort {
            actual: frame.len(),
            min: TCP_PREAMBLE_LEN,
        });
    }
    let preamble: [u8; TCP_PREAMBLE_LEN] =
        frame[..TCP_PREAMBLE_LEN]
            .try_into()
            .map_err(|_| ProtocolError::FrameTooShort {
                actual: frame.len(),
                min: TCP_PREAMBLE_LEN,
            })?;
    let header = validate_tcp_frame_preamble(&preamble)?;
    let remaining = &frame[TCP_PREAMBLE_LEN..];
    if remaining.len() != header.remaining_len {
        return Err(ProtocolError::InvalidPayload(
            "フレーム長と実データ長が一致しません".to_string(),
        ));
    }
    decode_tcp_file_chunk_body(msg_key, &header, remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_binary_frame_roundtrip_and_aad_version_checks() {
        let beacon_key = [0x11u8; 32];
        let other_key = [0x22u8; 32];

        let beacon = UdpPayload::Beacon {
            peer_id: "peer-uuid-1".to_string(),
            display_name: "田中".to_string(),
            tcp_port: 45101,
            status: UserStatus::Online,
            timestamp: 1_700_000_000,
            seq: 1,
            advertised_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 6))),
        };
        let frame = encode_udp_frame(&beacon_key, &beacon).unwrap();
        assert!(frame.len() <= MAX_UDP_PACKET_BYTES);
        assert_eq!(&frame[0..4], b"ZHOP");
        assert_eq!(&frame[4..6], &4u16.to_be_bytes());

        let decoded = decode_udp_frame(&beacon_key, &frame).unwrap();
        assert_eq!(decoded, beacon);

        let bye = UdpPayload::Bye {
            peer_id: "peer-uuid-1".to_string(),
            timestamp: 1_700_000_010,
            seq: 2,
            advertised_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 6))),
        };
        let bye_frame = encode_udp_frame(&beacon_key, &bye).unwrap();
        assert_eq!(decode_udp_frame(&beacon_key, &bye_frame).unwrap(), bye);

        // 鍵不一致
        assert_eq!(
            decode_udp_frame(&other_key, &frame),
            Err(ProtocolError::DecryptionFailed)
        );

        // バージョン不一致
        let mut wrong_ver = frame.clone();
        wrong_ver[5] = 3;
        assert_eq!(
            decode_udp_frame(&beacon_key, &wrong_ver),
            Err(ProtocolError::VersionMismatch {
                received_version: 3
            })
        );

        // magic 不正
        let mut bad_magic = frame.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            decode_udp_frame(&beacon_key, &bad_magic),
            Err(ProtocolError::InvalidMagic)
        );

        // 上限超過
        let oversized = vec![0u8; MAX_UDP_PACKET_BYTES + 1];
        assert_eq!(
            decode_udp_frame(&beacon_key, &oversized),
            Err(ProtocolError::FrameTooLarge {
                actual: MAX_UDP_PACKET_BYTES + 1,
                max: MAX_UDP_PACKET_BYTES
            })
        );
    }

    #[test]
    fn tcp_control_frames_roundtrip_and_preamble_guards() {
        let msg_key = [0x55u8; 32];
        let payloads = vec![
            TcpPayload::Hello {
                sender_id: "p1".to_string(),
                sender_name: "Alice".to_string(),
                tcp_port: 45101,
                status: UserStatus::Away,
                timestamp: 100,
                seq: 1,
                advertised_ip: Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 10, 6))),
            },
            TcpPayload::Chat {
                message_id: "m1".to_string(),
                sender_id: "p1".to_string(),
                sender_name: "Alice".to_string(),
                is_broadcast: false,
                body: "暗号化バイナリフレーム".to_string(),
                timestamp: 101,
                reply_to_id: Some("m0".to_string()),
                reply_to_sender: Some("Bob".to_string()),
                reply_to_preview: Some("元メッセージ".to_string()),
            },
            TcpPayload::Ack {
                message_id: "m1".to_string(),
                receiver_id: "p2".to_string(),
                timestamp: 102,
            },
            TcpPayload::FileOffer {
                transfer_id: "t1".to_string(),
                sender_id: "p1".to_string(),
                filename: "memo.txt".to_string(),
                file_size: 1024,
                sha256_hex: "abcd".to_string(),
                timestamp: 103,
            },
            TcpPayload::FileResponse {
                transfer_id: "t1".to_string(),
                sender_id: "p2".to_string(),
                accepted: true,
                timestamp: 104,
            },
            TcpPayload::DeleteMessage {
                message_id: "m1".to_string(),
                sender_id: "p1".to_string(),
                is_broadcast: true,
                timestamp: 105,
            },
        ];

        for item in payloads {
            let frame = encode_tcp_control_frame(&msg_key, &item).unwrap();
            let decoded = decode_tcp_control_frame(&msg_key, &frame).unwrap();
            assert_eq!(decoded, item);
        }

        // preamble 事前検査: 16 KiB 超・未知 kind・非ゼロ reserved・バージョン不一致
        let mut pre = [0u8; TCP_PREAMBLE_LEN];
        pre[0..4].copy_from_slice(&((MAX_TCP_CONTROL_FRAME_BYTES as u32) + 1).to_be_bytes());
        pre[4..6].copy_from_slice(&4u16.to_be_bytes());
        pre[6] = FrameKind::ControlJson as u8;
        pre[7] = 0;
        assert_eq!(
            validate_tcp_frame_preamble(&pre),
            Err(ProtocolError::FrameTooLarge {
                actual: MAX_TCP_CONTROL_FRAME_BYTES + 1,
                max: MAX_TCP_CONTROL_FRAME_BYTES
            })
        );

        pre[0..4].copy_from_slice(&64u32.to_be_bytes());
        pre[6] = 0x7F;
        assert_eq!(
            validate_tcp_frame_preamble(&pre),
            Err(ProtocolError::UnsupportedFrameKind(0x7F))
        );

        pre[6] = FrameKind::ControlJson as u8;
        pre[7] = 1;
        assert_eq!(
            validate_tcp_frame_preamble(&pre),
            Err(ProtocolError::InvalidReservedByte(1))
        );

        pre[7] = 0;
        pre[5] = 9;
        assert_eq!(
            validate_tcp_frame_preamble(&pre),
            Err(ProtocolError::VersionMismatch {
                received_version: 9
            })
        );
    }

    #[test]
    fn tcp_file_chunk_uses_raw_binary_without_json_expansion_and_checks_aad() {
        let msg_key = [0x77u8; 32];
        let header = FileChunkHeader {
            transfer_id: "tr-1".to_string(),
            sender_id: "p1".to_string(),
            chunk_index: 3,
            timestamp: 1_700_000_000,
        };
        let raw_chunk = vec![0xABu8; MAX_FILE_CHUNK_RAW_BYTES]; // 64 KiB
        let frame = encode_tcp_file_chunk_frame(&msg_key, &header, &raw_chunk).unwrap();

        // JSON 配列膨張（約4倍 = 262 KiB）が起きず、約 64 KiB + 数百バイトに収まること
        assert!(frame.len() < 66 * 1024);

        let (dec_header, dec_bytes) = decode_tcp_file_chunk_frame(&msg_key, &frame).unwrap();
        assert_eq!(dec_header, header);
        assert_eq!(&*dec_bytes, &raw_chunk);

        // AAD（reserved バイト等）が改ざんされた場合は事前検査または復号で拒否
        let mut tampered = frame.clone();
        tampered[20] ^= 0xFF;
        assert_eq!(
            decode_tcp_file_chunk_frame(&msg_key, &tampered),
            Err(ProtocolError::DecryptionFailed)
        );
    }

    #[test]
    fn legacy_chat_json_without_reply_fields_decodes_backward_compatibly() {
        let msg_key = [0x44u8; 32];
        let legacy_json = br#"{"kind":"Chat","message_id":"m-old","sender_id":"p1","sender_name":"Alice","is_broadcast":true,"body":"legacy","timestamp":12345}"#;
        let frame = build_tcp_frame(&msg_key, FrameKind::ControlJson, legacy_json).unwrap();
        let decoded = decode_tcp_control_frame(&msg_key, &frame).unwrap();
        assert_eq!(
            decoded,
            TcpPayload::Chat {
                message_id: "m-old".to_string(),
                sender_id: "p1".to_string(),
                sender_name: "Alice".to_string(),
                is_broadcast: true,
                body: "legacy".to_string(),
                timestamp: 12345,
                reply_to_id: None,
                reply_to_sender: None,
                reply_to_preview: None,
            }
        );
    }
}
