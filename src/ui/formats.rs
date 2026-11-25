//! UI 表示用純粋フォーマット・時刻変換・通信情報生成・スレッド移行ヘルパー。

use std::mem::{size_of, zeroed};
use std::net::{SocketAddr, TcpStream};
use std::ptr::null;
use std::time::Duration;

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

use zerohop::domain::model::{DeliveryState, MAX_CHAT_BODY_BYTES, PeerView, ThreadKey};
use zerohop::network::nic::NicInfo;

use super::state_helpers::UiState;

pub(crate) fn normalized_utf8_byte_len(raw: &str) -> usize {
    let mut bytes = 0usize;
    let mut prev_cr = false;
    for ch in raw.chars() {
        if ch == '\r' {
            bytes += 1;
            prev_cr = true;
            continue;
        }
        if ch == '\n' {
            if prev_cr {
                prev_cr = false;
                continue;
            }
            bytes += 1;
            continue;
        }
        prev_cr = false;
        if ch == '\t' || !ch.is_control() {
            bytes += ch.len_utf8();
        }
    }
    bytes
}

fn unix_ts_to_local_systemtime(ts: i64) -> Option<SYSTEMTIME> {
    if ts < 0 {
        return None;
    }
    const WINDOWS_TO_UNIX_EPOCH_SECS: i64 = 11_644_473_600;
    let shifted = ts.checked_add(WINDOWS_TO_UNIX_EPOCH_SECS)?;
    if shifted < 0 {
        return None;
    }
    let intervals_100ns = u64::try_from(shifted).ok()?.checked_mul(10_000_000)?;
    let ft = FILETIME {
        dwLowDateTime: (intervals_100ns & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (intervals_100ns >> 32) as u32,
    };
    let mut utc_st: SYSTEMTIME = unsafe { zeroed() };
    let mut local_st: SYSTEMTIME = unsafe { zeroed() };
    unsafe {
        if FileTimeToSystemTime(&raw const ft, &raw mut utc_st) == 0 {
            return None;
        }
        if SystemTimeToTzSpecificLocalTime(null(), &raw const utc_st, &raw mut local_st) == 0 {
            return Some(utc_st);
        }
    }
    Some(local_st)
}

pub(crate) fn format_unix_time_hms(ts: i64) -> String {
    if let Some(st) = unix_ts_to_local_systemtime(ts) {
        format!("{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond)
    } else if ts >= 0 {
        let day_secs = ts % 86_400;
        let h = day_secs / 3_600;
        let m = (day_secs % 3_600) / 60;
        let s = day_secs % 60;
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        "--:--:--".to_string()
    }
}

pub(crate) fn format_unix_datetime(ts: i64) -> String {
    if let Some(st) = unix_ts_to_local_systemtime(ts) {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    } else {
        format!("UNIX:{ts}")
    }
}

pub(crate) fn summarize_message_body(body: &str, max_chars: usize) -> String {
    let single = body.replace("\r\n", " / ").replace('\n', " / ");
    let has_nl = body.contains('\n');
    let count = single.chars().count();
    if has_nl || count > max_chars {
        let head: String = single.chars().take(max_chars).collect();
        format!("{head}… [Enterで全文]")
    } else {
        single
    }
}

pub(crate) fn normalize_crlf(body: &str) -> String {
    body.replace("\r\n", "\n").replace('\n', "\r\n")
}

pub(crate) fn format_bytes_human(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub(crate) fn format_remaining_bytes_label(
    current_utf8_bytes: usize,
    send_on_enter: bool,
) -> String {
    let hint = if send_on_enter {
        "送信: Enter / 改行: Shift+Enter"
    } else {
        "送信: Ctrl+Enter / 改行: Enter"
    };
    if current_utf8_bytes <= MAX_CHAT_BODY_BYTES {
        let rem = MAX_CHAT_BODY_BYTES - current_utf8_bytes;
        format!("残り {rem} / {MAX_CHAT_BODY_BYTES} バイト（{hint}）")
    } else {
        let over = current_utf8_bytes - MAX_CHAT_BODY_BYTES;
        format!("上限を {over} バイト超過しています（最大 {MAX_CHAT_BODY_BYTES} バイト）")
    }
}

pub(crate) fn is_message_retryable(delivery: &DeliveryState) -> bool {
    match delivery {
        DeliveryState::DirectFailed | DeliveryState::DirectSending => true,
        DeliveryState::Broadcast {
            target_count,
            acked_peers,
            failed_peers,
        } => *target_count > 0 && (!failed_peers.is_empty() || acked_peers.len() < *target_count),
        DeliveryState::Received | DeliveryState::DirectDelivered => false,
    }
}

pub(crate) fn resolve_migrated_thread(current: &ThreadKey, new_peers: &[PeerView]) -> ThreadKey {
    let ThreadKey::Peer(cur_id) = current else {
        return ThreadKey::Broadcast;
    };
    if new_peers.iter().any(|p| &p.peer_id == cur_id) {
        return current.clone();
    }
    if let Some(rest) = cur_id.strip_prefix("manual:")
        && let Some((ip_part, port_part)) = rest.rsplit_once(':')
        && let Ok(port) = port_part.parse::<u16>()
        && let Some(formal) = new_peers
            .iter()
            .find(|p| p.ip_text == ip_part && p.tcp_port == port)
    {
        return ThreadKey::Peer(formal.peer_id.clone());
    }
    ThreadKey::Broadcast
}

pub(crate) fn get_process_working_set_bytes() -> Option<usize> {
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut pmc, pmc.cb) };
    (ok != 0).then_some(pmc.WorkingSetSize)
}

pub(crate) fn run_loopback_connectivity_diagnostic(
    tcp_port: u16,
    nic_info: Option<&NicInfo>,
) -> String {
    let tcp_diag = if tcp_port == 0 {
        "未待受 (TCPポート=0)".to_string()
    } else {
        let addr = SocketAddr::from(([127, 0, 0, 1], tcp_port));
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => format!("ループバックTCP待受応答: OK (127.0.0.1:{tcp_port})"),
            Err(err) => format!(
                "ループバックTCP待受応答: NG (127.0.0.1:{tcp_port} - {:?})",
                err.kind()
            ),
        }
    };
    let udp_diag = match nic_info {
        Some(n) => format!("UDPブロードキャスト対象: {} -> {}", n.ip, n.broadcast),
        None => "UDPブロードキャスト対象: 既定バインド (NIC未指定)".to_string(),
    };
    format!("{tcp_diag}\n  {udp_diag}")
}

pub(crate) fn build_connection_info_text(state: &UiState) -> String {
    let ws = get_process_working_set_bytes()
        .map(format_bytes_human)
        .unwrap_or_else(|| "計測不可".to_string());
    let nic_desc = match &state.nic_info {
        Some(n) => format!(
            "{} ({}) / {} (Broadcast: {})",
            n.friendly_name, n.description, n.ip, n.broadcast
        ),
        None => "物理NIC未検出 / 既定バインド".to_string(),
    };
    let mode_label = if state.multi_instance {
        "多重起動許可 (--multi)"
    } else {
        "標準単一起動"
    };

    let mut lines = vec![
        format!("表示名: {}", state.display_name),
        format!("現在の状態: {}", state.status.label_ja()),
        format!("起動モード: {mode_label}"),
        format!("ルーム確認コード: {}", state.room_code),
        format!("エフェメラル端末ID: {}", state.ephemeral_peer_id),
        format!("使用NIC: {nic_desc}"),
        format!(
            "待受ポート: TCP {} / UDP {}",
            state.tcp_port, state.udp_port
        ),
        format!(
            "会話ログ使用量: {} / 上限 {} MiB",
            format_bytes_human(state.total_log_bytes),
            state.config.max_memory_mb
        ),
        format!("プロセス Working Set: {ws}"),
        String::new(),
        "[簡易疎通診断]".to_string(),
        format!(
            "  {}",
            run_loopback_connectivity_diagnostic(state.tcp_port, state.nic_info.as_ref())
        ),
        String::new(),
        format!("検出・追加済みピア ({}件):", state.peers.len()),
    ];
    if state.peers.is_empty() {
        lines.push("  （なし）".to_string());
    } else {
        for p in &state.peers {
            lines.push(format!(
                "  - {} ({}:{}) [{}] ID:{}",
                p.display_name,
                p.ip_text,
                p.tcp_port,
                if p.is_online {
                    p.status.label_ja()
                } else {
                    "オフライン"
                },
                p.short_id
            ));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use zerohop::domain::model::UserStatus;

    use super::*;

    #[test]
    fn summarize_message_body_handles_multiline_and_long_text() {
        assert_eq!(summarize_message_body("こんにちは", 20), "こんにちは");
        assert_eq!(
            summarize_message_body("1行目\n2行目", 20),
            "1行目 / 2行目… [Enterで全文]"
        );
        let long = "あ".repeat(80);
        let summary = summarize_message_body(&long, 70);
        assert!(summary.ends_with("… [Enterで全文]"));
        assert_eq!(summary.chars().take(70).count(), 70);
    }

    #[test]
    fn normalize_crlf_converts_lf_without_doubling() {
        assert_eq!(normalize_crlf("a\nb\r\nc"), "a\r\nb\r\nc");
    }

    #[test]
    fn format_bytes_human_and_remaining_guide() {
        assert_eq!(format_bytes_human(512), "512 B");
        assert_eq!(format_bytes_human(1536), "1.5 KB");
        assert_eq!(format_bytes_human(2 * 1024 * 1024), "2.00 MB");
        let label_ctrl = format_remaining_bytes_label(100, false);
        assert!(label_ctrl.contains("3996 / 4096"));
        assert!(label_ctrl.contains("送信: Ctrl+Enter"));
        let label_enter = format_remaining_bytes_label(100, true);
        assert!(label_enter.contains("送信: Enter / 改行: Shift+Enter"));
        assert!(format_remaining_bytes_label(4100, false).contains("4 バイト超過"));
    }

    #[test]
    fn unix_time_format_outputs_valid_hms_and_datetime() {
        let hms = format_unix_time_hms(1_700_000_000);
        assert_eq!(hms.len(), 8);
        assert_eq!(&hms[2..3], ":");
        assert_eq!(&hms[5..6], ":");
        assert_eq!(format_unix_time_hms(-1), "--:--:--");

        let dt = format_unix_datetime(1_700_000_000);
        assert_eq!(dt.len(), 19);
    }

    #[test]
    fn delivery_retryable_and_thread_migration_follow_rules() {
        assert!(!is_message_retryable(&DeliveryState::Received));
        assert!(!is_message_retryable(&DeliveryState::DirectDelivered));
        assert!(is_message_retryable(&DeliveryState::DirectFailed));
        assert!(is_message_retryable(&DeliveryState::DirectSending));

        let mut acked = HashSet::new();
        acked.insert("p1".to_string());
        assert!(!is_message_retryable(&DeliveryState::Broadcast {
            target_count: 1,
            acked_peers: acked.clone(),
            failed_peers: Vec::new(),
        }));
        assert!(is_message_retryable(&DeliveryState::Broadcast {
            target_count: 2,
            acked_peers: acked,
            failed_peers: vec!["p2".to_string()],
        }));

        let formal = PeerView {
            peer_id: "uuid-bob".to_string(),
            display_name: "Bob".to_string(),
            short_id: "uuid-bob".to_string(),
            ip_text: "127.0.0.1".to_string(),
            tcp_port: 45102,
            status: UserStatus::Online,
            is_online: true,
            unread_count: 0,
        };
        assert_eq!(
            resolve_migrated_thread(
                &ThreadKey::Peer("manual:127.0.0.1:45102".to_string()),
                &[formal]
            ),
            ThreadKey::Peer("uuid-bob".to_string())
        );
        assert_eq!(
            resolve_migrated_thread(&ThreadKey::Peer("missing".to_string()), &[]),
            ThreadKey::Broadcast
        );
    }

    #[test]
    fn normalized_utf8_byte_len_matches_validated_chat_body_len() {
        for sample in [
            "こんにちは\r\n2行目\r\t項目\x07\x1b末尾",
            "絵文字😊と日本語",
            "line1\nline2",
        ] {
            let expected = zerohop::domain::validation::validate_chat_body(sample)
                .unwrap()
                .len();
            assert_eq!(normalized_utf8_byte_len(sample), expected);
        }
        assert_eq!(normalized_utf8_byte_len("\x00\x07\r"), 1);
    }

    #[test]
    fn loopback_connectivity_diagnostic_reports_ok_for_bound_listener_and_zero_port() {
        let zero = run_loopback_connectivity_diagnostic(0, None);
        assert!(zero.contains("未待受"));
        assert!(zero.contains("既定バインド"));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let ok = run_loopback_connectivity_diagnostic(port, None);
        assert!(ok.contains("ループバックTCP待受応答: OK"));
        drop(listener);
    }
}
