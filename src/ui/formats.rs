//! UI 表示用純粋フォーマット・時刻変換・通信情報生成・スレッド移行ヘルパー。

use std::mem::{size_of, zeroed};
use std::net::{SocketAddr, TcpStream};
use std::ptr::null;
use std::time::Duration;

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

use zerohop::domain::model::{DeliveryState, InMemoryChatMessage, PeerView, ThreadKey};
use zerohop::network::nic::NicInfo;
use zeroize::Zeroizing;

use super::state_helpers::UiState;

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

fn sanitize_filename_segment(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_control() || matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            out.push('_');
        } else {
            out.push(ch);
        }
        if out.chars().count() >= 40 {
            break;
        }
    }
    let trimmed = out.trim_matches(|c: char| c.is_whitespace() || c == '.');
    if trimmed.is_empty() {
        "chat".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn default_chat_log_filename(thread_label: &str, now_unix_secs: i64) -> String {
    let safe_label = sanitize_filename_segment(thread_label);
    let stamp = if let Some(st) = unix_ts_to_local_systemtime(now_unix_secs) {
        format!(
            "{:04}{:02}{:02}_{:02}{:02}{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        )
    } else {
        "00000000_000000".to_string()
    };
    format!("ZeroHop_{safe_label}_{stamp}.txt")
}

pub(crate) fn format_chat_log_export_text(
    thread_label: &str,
    exported_at_text: &str,
    messages: &[InMemoryChatMessage],
) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    out.push_str("ZeroHop 会話ログ\r\n");
    out.push_str(&format!("スレッド: {thread_label}\r\n"));
    out.push_str(&format!("出力日時: {exported_at_text}\r\n"));
    out.push_str(&format!("件数: {}件\r\n", messages.len()));
    out.push_str("----------------------------------------\r\n");
    for msg in messages {
        let dt = format_unix_datetime(msg.timestamp);
        let body_crlf = Zeroizing::new(normalize_crlf(&msg.body));
        if let Some(reply) = &msg.reply_to {
            out.push_str(&format!(
                "  返信先: {}「{}」\r\n",
                reply.sender_name, reply.preview
            ));
        }
        out.push_str(&format!("[{dt}] {}: {}\r\n", msg.sender_name, *body_crlf));
    }
    out
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

pub(crate) fn is_message_retryable(delivery: &DeliveryState, is_deleted: bool) -> bool {
    if is_deleted {
        return false;
    }
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
    fn format_bytes_human_formats_units() {
        assert_eq!(format_bytes_human(512), "512 B");
        assert_eq!(format_bytes_human(1536), "1.5 KB");
        assert_eq!(format_bytes_human(2 * 1024 * 1024), "2.00 MB");
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
        assert!(!is_message_retryable(&DeliveryState::Received, false));
        assert!(!is_message_retryable(
            &DeliveryState::DirectDelivered,
            false
        ));
        assert!(is_message_retryable(&DeliveryState::DirectFailed, false));
        assert!(is_message_retryable(&DeliveryState::DirectSending, false));
        assert!(!is_message_retryable(&DeliveryState::DirectFailed, true));

        let mut acked = HashSet::new();
        acked.insert("p1".to_string());
        assert!(!is_message_retryable(
            &DeliveryState::Broadcast {
                target_count: 1,
                acked_peers: acked.clone(),
                failed_peers: Vec::new(),
            },
            false,
        ));
        assert!(is_message_retryable(
            &DeliveryState::Broadcast {
                target_count: 2,
                acked_peers: acked,
                failed_peers: vec!["p2".to_string()],
            },
            false,
        ));

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

    #[test]
    fn default_chat_log_filename_sanitizes_forbidden_windows_chars() {
        let name = default_chat_log_filename("Alice<>:\"/\\|?* .", 1_700_000_000);
        assert!(name.starts_with("ZeroHop_Alice"));
        assert!(name.ends_with(".txt"));
        let stem = name.trim_start_matches("ZeroHop_");
        assert!(!stem.contains('<'));
        assert!(!stem.contains('>'));
        assert!(!stem.contains(':'));
        assert!(!stem.contains('"'));
        assert!(!stem.contains('/'));
        assert!(!stem.contains('\\'));
        assert!(!stem.contains('|'));
        assert!(!stem.contains('?'));
        assert!(!stem.contains('*'));

        let empty_name = default_chat_log_filename("...   ", 1_700_000_000);
        assert!(empty_name.starts_with("ZeroHop_chat_"));
    }

    #[test]
    fn format_chat_log_export_text_uses_crlf_and_expected_header() {
        let m1 = InMemoryChatMessage::new(
            "id-1",
            "peer-a",
            "Alice",
            "1行目\n2行目",
            1_700_000_000,
            DeliveryState::Received,
        );
        let m2 = InMemoryChatMessage::new(
            "id-2",
            "me",
            "自分",
            "了解しました",
            1_700_000_060,
            DeliveryState::DirectDelivered,
        )
        .with_reply_to(Some(zerohop::domain::model::ReplyReference {
            message_id: "id-1".to_string(),
            sender_name: "Alice".to_string(),
            preview: "1行目 2行目".to_string(),
        }));
        let text = format_chat_log_export_text("Alice", "2026-11-26 12:00:00", &[m1, m2]);
        assert!(text.contains("ZeroHop 会話ログ\r\n"));
        assert!(text.contains("スレッド: Alice\r\n"));
        assert!(text.contains("出力日時: 2026-11-26 12:00:00\r\n"));
        assert!(text.contains("件数: 2件\r\n"));
        assert!(text.contains("Alice: 1行目\r\n2行目\r\n"));
        assert!(text.contains("  返信先: Alice「1行目 2行目」\r\n"));
        assert!(text.contains("自分: 了解しました\r\n"));
        // 単独 LF が残っていないこと
        assert!(!text.replace("\r\n", "").contains('\n'));
    }
}
