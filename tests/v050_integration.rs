use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use zerohop::app::coordinator::{AppHandle, CoordinatorOptions, spawn_coordinator};
use zerohop::app::state::{AppEvent, UiCommand};
use zerohop::domain::model::{DELETED_MESSAGE_PLACEHOLDER, ReplyReference, ThreadKey};
use zerohop::storage::paths::AppPaths;

static V050_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_base_dir(name: &str) -> PathBuf {
    let seq = V050_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("zhop_v050_{name}_{}_{seq}", std::process::id()));
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
async fn delete_own_message_syncs_to_peer_and_rejects_deleting_others_message() {
    let dir_a = temp_base_dir("alice");
    let dir_b = temp_base_dir("bob");
    let (alice, rx_a) = spawn_test_node(&dir_a);
    let (bob, rx_b) = spawn_test_node(&dir_b);

    let pass = "V050DeleteTest!99";
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

    let ev_a = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let alice_port = match ev_a {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };
    let ev_b = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let bob_port = match ev_b {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };

    alice
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: bob_port,
        })
        .await
        .unwrap();
    bob.cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: alice_port,
        })
        .await
        .unwrap();

    let bob_id_on_alice = loop {
        let ev = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
            matches!(ev, AppEvent::PeerListChanged(_))
        })
        .await;
        if let AppEvent::PeerListChanged(peers) = ev
            && let Some(p) = peers.iter().find(|p| p.display_name == "Bob")
        {
            break p.peer_id.clone();
        }
    };
    let alice_id_on_bob = loop {
        let ev = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
            matches!(ev, AppEvent::PeerListChanged(_))
        })
        .await;
        if let AppEvent::PeerListChanged(peers) = ev
            && let Some(p) = peers.iter().find(|p| p.display_name == "Alice")
        {
            break p.peer_id.clone();
        }
    };

    let alice_thread_on_bob = ThreadKey::Peer(alice_id_on_bob);
    let bob_thread_on_alice = ThreadKey::Peer(bob_id_on_alice);

    // 1. Alice が Bob へ送信し、Bob が受信する
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: bob_thread_on_alice.clone(),
            body: Zeroizing::new("後で取り消すメッセージ".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;

    // 2. Bob も Alice へ返信し、Alice が受信する
    bob.cmd_tx
        .send(UiCommand::SendChat {
            thread: alice_thread_on_bob.clone(),
            body: Zeroizing::new("Bobの大切なメッセージ".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;

    let alice_msgs = alice
        .log_reader
        .export_thread_messages(&bob_thread_on_alice);
    assert_eq!(alice_msgs.len(), 2);
    let alice_own_msg_id = alice_msgs[0].message_id.clone();
    let bob_msg_id_on_alice = alice_msgs[1].message_id.clone();

    // 3. Alice が自分の投稿を削除 -> Bob 側へも同期されプレースホルダへ置換される
    alice
        .cmd_tx
        .send(UiCommand::DeleteMessage {
            thread: bob_thread_on_alice.clone(),
            message_id: alice_own_msg_id,
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ThreadUpdated { .. })
    })
    .await;
    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ThreadUpdated { .. })
    })
    .await;

    let alice_after = alice
        .log_reader
        .export_thread_messages(&bob_thread_on_alice);
    assert!(alice_after[0].is_deleted);
    assert_eq!(alice_after[0].body, DELETED_MESSAGE_PLACEHOLDER);

    let bob_after = bob.log_reader.export_thread_messages(&alice_thread_on_bob);
    assert!(bob_after[0].is_deleted);
    assert_eq!(bob_after[0].body, DELETED_MESSAGE_PLACEHOLDER);

    // 4. Alice が他人の投稿（Bob の投稿）を削除しようとしても無視される
    alice
        .cmd_tx
        .send(UiCommand::DeleteMessage {
            thread: bob_thread_on_alice.clone(),
            message_id: bob_msg_id_on_alice,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;

    let alice_final = alice
        .log_reader
        .export_thread_messages(&bob_thread_on_alice);
    assert!(!alice_final[1].is_deleted);
    assert_eq!(alice_final[1].body, "Bobの大切なメッセージ");

    let bob_final = bob.log_reader.export_thread_messages(&alice_thread_on_bob);
    assert!(!bob_final[1].is_deleted);
    assert_eq!(bob_final[1].body, "Bobの大切なメッセージ");

    let _ = alice.cmd_tx.send(UiCommand::Logout).await;
    let _ = bob.cmd_tx.send(UiCommand::Logout).await;
    let _ = alice.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = bob.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_message_syncs_reply_reference_between_peers() {
    let dir_a = temp_base_dir("reply_alice");
    let dir_b = temp_base_dir("reply_bob");
    let (alice, rx_a) = spawn_test_node(&dir_a);
    let (bob, rx_b) = spawn_test_node(&dir_b);

    let pass = "V050ReplyTest!99";
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

    let ev_a = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let alice_port = match ev_a {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };
    let ev_b = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let bob_port = match ev_b {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };

    alice
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: bob_port,
        })
        .await
        .unwrap();
    bob.cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: alice_port,
        })
        .await
        .unwrap();

    let bob_id_on_alice = loop {
        let ev = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
            matches!(ev, AppEvent::PeerListChanged(_))
        })
        .await;
        if let AppEvent::PeerListChanged(peers) = ev
            && let Some(p) = peers.iter().find(|p| p.display_name == "Bob")
        {
            break p.peer_id.clone();
        }
    };
    let alice_id_on_bob = loop {
        let ev = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
            matches!(ev, AppEvent::PeerListChanged(_))
        })
        .await;
        if let AppEvent::PeerListChanged(peers) = ev
            && let Some(p) = peers.iter().find(|p| p.display_name == "Alice")
        {
            break p.peer_id.clone();
        }
    };

    let bob_thread_on_alice = ThreadKey::Peer(bob_id_on_alice);
    let alice_thread_on_bob = ThreadKey::Peer(alice_id_on_bob);

    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: bob_thread_on_alice.clone(),
            body: Zeroizing::new("明日の会議は何時からですか？".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;

    let bob_msgs = bob.log_reader.export_thread_messages(&alice_thread_on_bob);
    let target_msg = &bob_msgs[0];
    let reply_ref = ReplyReference {
        message_id: target_msg.message_id.clone(),
        sender_name: target_msg.sender_name.clone(),
        preview: target_msg.body.clone(),
    };

    bob.cmd_tx
        .send(UiCommand::SendChat {
            thread: alice_thread_on_bob.clone(),
            body: Zeroizing::new("10時からです。".to_string()),
            reply_to: Some(reply_ref.clone()),
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;

    let alice_msgs = alice
        .log_reader
        .export_thread_messages(&bob_thread_on_alice);
    assert_eq!(alice_msgs.len(), 2);
    assert_eq!(alice_msgs[1].body, "10時からです。");
    assert_eq!(alice_msgs[1].reply_to, Some(reply_ref));

    let _ = alice.cmd_tx.send(UiCommand::Logout).await;
    let _ = bob.cmd_tx.send(UiCommand::Logout).await;
    let _ = alice.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = bob.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mention_sets_is_mentioned_true_only_for_exact_target_display_name() {
    let dir_a = temp_base_dir("mention_alice");
    let dir_b = temp_base_dir("mention_bob");
    let (alice, rx_a) = spawn_test_node(&dir_a);
    let (bob, rx_b) = spawn_test_node(&dir_b);

    let pass = "V050MentionTest!99";
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

    let ev_a = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let alice_port = match ev_a {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };
    let ev_b = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LoginSucceeded { .. })
    })
    .await;
    let bob_port = match ev_b {
        AppEvent::LoginSucceeded { tcp_port, .. } => tcp_port,
        _ => unreachable!(),
    };

    alice
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: bob_port,
        })
        .await
        .unwrap();
    bob.cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: alice_port,
        })
        .await
        .unwrap();

    let bob_id_on_alice = loop {
        let ev = wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
            matches!(ev, AppEvent::PeerListChanged(_))
        })
        .await;
        if let AppEvent::PeerListChanged(peers) = ev
            && let Some(p) = peers.iter().find(|p| p.display_name == "Bob")
        {
            break p.peer_id.clone();
        }
    };
    let bob_thread_on_alice = ThreadKey::Peer(bob_id_on_alice);

    // 1. @Bob へのメンションは is_mentioned == true
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: bob_thread_on_alice.clone(),
            body: Zeroizing::new("@Bob 資料を確認してください".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    let ev_hit = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;
    match ev_hit {
        AppEvent::IncomingMessageReceived { is_mentioned, .. } => assert!(is_mentioned),
        _ => unreachable!(),
    }

    // 2. @Bob2 への別名メンションは is_mentioned == false
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: bob_thread_on_alice,
            body: Zeroizing::new("@Bob2 への連絡です".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    let ev_miss = wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::IncomingMessageReceived { .. })
    })
    .await;
    match ev_miss {
        AppEvent::IncomingMessageReceived { is_mentioned, .. } => assert!(!is_mentioned),
        _ => unreachable!(),
    }

    let _ = alice.cmd_tx.send(UiCommand::Logout).await;
    let _ = bob.cmd_tx.send(UiCommand::Logout).await;
    let _ = alice.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = bob.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
