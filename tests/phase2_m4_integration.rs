use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use zerohop::app::coordinator::{AppHandle, CoordinatorOptions, spawn_coordinator};
use zerohop::app::state::{AppEvent, UiCommand};
use zerohop::domain::model::ThreadKey;
use zerohop::storage::paths::AppPaths;

static PH2_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_base_dir(name: &str) -> PathBuf {
    let seq = PH2_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("zhop_ph2_{name}_{}_{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn wait_for_event<F>(rx: &Receiver<AppEvent>, timeout: Duration, mut pred: F) -> AppEvent
where
    F: FnMut(&AppEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    loop {
        loop {
            match rx.try_recv() {
                Ok(ev) => {
                    if pred(&ev) {
                        return ev;
                    }
                    seen.push(ev);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("AppEvent channel disconnected; seen={seen:?}");
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for AppEvent; seen={seen:?}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn spawn_test_node(dir: &Path) -> (AppHandle, Receiver<AppEvent>) {
    let paths = AppPaths::from_base_dir(dir.to_path_buf());
    let (tx, rx) = mpsc::channel();
    let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let handle = spawn_coordinator(CoordinatorOptions::loopback_for_test(paths), tx, wake);
    (handle, rx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn screen_lock_retains_inbound_verifies_password_searches_and_allows_direct_logout() {
    let dir_a = temp_base_dir("alice");
    let dir_b = temp_base_dir("bob");
    let (alice, rx_a) = spawn_test_node(&dir_a);
    let (bob, rx_b) = spawn_test_node(&dir_b);

    let pass = "Phase2LockPass!99";
    alice
        .cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: "Alice".to_string(),
            password: Zeroizing::new(pass.to_string()),
        })
        .await
        .unwrap();
    bob.cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: "Bob".to_string(),
            password: Zeroizing::new(pass.to_string()),
        })
        .await
        .unwrap();

    let alice_port = match wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await
    {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };

    let bob_id = match wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await
    {
        AppEvent::LoginSucceeded {
            ephemeral_peer_id, ..
        } => ephemeral_peer_id,
        _ => unreachable!(),
    };

    bob.cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: alice_port,
        })
        .await
        .unwrap();

    let alice_id_on_bob = match wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::PeerListChanged(peers) if peers.iter().any(|p| p.display_name == "Alice"))
    })
    .await
    {
        AppEvent::PeerListChanged(peers) => peers
            .into_iter()
            .find(|p| p.display_name == "Alice")
            .unwrap()
            .peer_id,
        _ => unreachable!(),
    };

    // Alice が画面ロック
    alice.cmd_tx.send(UiCommand::LockScreen).await.unwrap();
    wait_for_event(&rx_a, Duration::from_secs(3), |ev| {
        matches!(ev, AppEvent::ScreenLocked)
    })
    .await;

    // ロック中の送信は無視される
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Peer(bob_id.clone()),
            body: Zeroizing::new("should-not-send".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();

    // Bob から Alice へ送信 -> ロック中でも受信・メモリ格納は継続される
    bob.cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Peer(alice_id_on_bob.clone()),
            body: Zeroizing::new("Urgent Meeting Notice".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::IncomingMessageReceived { sender_name, .. } if sender_name == "Bob"
        )
    })
    .await;

    // 誤パスワードでは解除不可
    alice
        .cmd_tx
        .send(UiCommand::UnlockScreen {
            password: Zeroizing::new("WrongPassword!00".to_string()),
        })
        .await
        .unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ScreenUnlockResult { ok: false })
    })
    .await;

    // 正パスワードで解除
    alice
        .cmd_tx
        .send(UiCommand::UnlockScreen {
            password: Zeroizing::new(pass.to_string()),
        })
        .await
        .unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ScreenUnlockResult { ok: true })
    })
    .await;

    // セッション内検索でロック中に受信したメッセージが見つかり、ロック中の送信は含まれない
    let hits = alice.log_reader.search(None, "urgent", 10);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].sender_name, "Bob");
    assert!(
        alice
            .log_reader
            .search(None, "should-not-send", 10)
            .is_empty()
    );

    // 再度ロックした状態から直接ログアウト全消去できること
    alice.cmd_tx.send(UiCommand::LockScreen).await.unwrap();
    wait_for_event(&rx_a, Duration::from_secs(3), |ev| {
        matches!(ev, AppEvent::ScreenLocked)
    })
    .await;
    alice.cmd_tx.send(UiCommand::Logout).await.unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LogoutCompleted)
    })
    .await;
    assert_eq!(alice.log_reader.total_bytes(), 0);
    assert!(alice.log_reader.search(None, "urgent", 10).is_empty());

    alice.cmd_tx.send(UiCommand::Shutdown).await.unwrap();
    bob.cmd_tx.send(UiCommand::Shutdown).await.unwrap();
    let _ = alice.join_handle.await;
    let _ = bob.join_handle.await;

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test]
async fn advertised_ip_mismatch_hello_emits_notification_event() {
    let dir = temp_base_dir("adv_ip_mismatch");
    let (node, rx) = spawn_test_node(&dir);
    let pass = "phase-b-adv-ip-test";

    node.cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: "Alice".to_string(),
            password: Zeroizing::new(pass.to_string()),
        })
        .await
        .unwrap();

    let tcp_port = match wait_for_event(&rx, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await
    {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        other => unreachable!("{other:?}"),
    };

    let keys = zerohop::crypto::kdf::derive_session_keys_with_params(
        pass,
        zerohop::crypto::kdf::Argon2Params {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .unwrap();
    let msg_key = keys.with_msg_key(|k| Zeroizing::new(*k)).unwrap();
    let now = zerohop::network::current_unix_timestamp();
    let bogus_adv: std::net::IpAddr = "10.99.88.77".parse().unwrap();
    let target: std::net::SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();

    let payload = zerohop::domain::protocol::TcpPayload::Hello {
        sender_id: "manual-peer-id-001".to_string(),
        sender_name: "RemotePeer".to_string(),
        tcp_port: 45999,
        status: zerohop::domain::model::UserStatus::Online,
        timestamp: now,
        seq: 1,
        advertised_ip: Some(bogus_adv),
    };
    zerohop::network::tcp_transport::send_tcp_control_frame(target, &msg_key, &payload)
        .await
        .unwrap();

    let ev = wait_for_event(&rx, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::AdvertisedIpMismatch { .. })
    })
    .await;
    match ev {
        AppEvent::AdvertisedIpMismatch {
            peer_ip,
            advertised_ip,
        } => {
            assert_eq!(peer_ip, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
            assert_eq!(advertised_ip, bogus_adv);
        }
        other => unreachable!("{other:?}"),
    }

    node.cmd_tx.send(UiCommand::Shutdown).await.unwrap();
    let _ = node.join_handle.await;
    let _ = std::fs::remove_dir_all(&dir);
}
