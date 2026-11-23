use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use lan_messenger::app::coordinator::{AppHandle, CoordinatorOptions, spawn_coordinator};
use lan_messenger::app::state::{AppEvent, UiCommand};
use lan_messenger::storage::paths::AppPaths;

static PH3_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_base_dir(name: &str) -> PathBuf {
    let seq = PH3_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("lmsg_ph3_{name}_{}_{seq}", std::process::id()));
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
async fn encrypted_file_transfer_accept_verify_and_reject_lifecycle() {
    let dir_a = temp_base_dir("node_a");
    let dir_b = temp_base_dir("node_b");
    let work_dir = temp_base_dir("work");

    let (node_a, rx_a) = spawn_test_node(&dir_a);
    let (node_b, rx_b) = spawn_test_node(&dir_b);

    let pass = Zeroizing::new("Phase3TransferPass!".to_string());
    node_a
        .cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: "Alice".to_string(),
            password: pass.clone(),
        })
        .await
        .unwrap();
    node_b
        .cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: "Bob".to_string(),
            password: pass,
        })
        .await
        .unwrap();

    let (id_a, _port_a) = match wait_for_event(&rx_a, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::LoginSucceeded { .. })
    })
    .await
    {
        AppEvent::LoginSucceeded {
            ephemeral_peer_id,
            tcp_port,
            ..
        } => (ephemeral_peer_id, tcp_port),
        _ => unreachable!(),
    };
    let (id_b, port_b) = match wait_for_event(&rx_b, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::LoginSucceeded { .. })
    })
    .await
    {
        AppEvent::LoginSucceeded {
            ephemeral_peer_id,
            tcp_port,
            ..
        } => (ephemeral_peer_id, tcp_port),
        _ => unreachable!(),
    };

    // 手動ピア追加で相互認識
    node_a
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: port_b,
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::PeerListChanged(list) if list.iter().any(|p| p.peer_id == id_b && p.is_online))
    })
    .await;
    wait_for_event(&rx_b, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::PeerListChanged(list) if list.iter().any(|p| p.peer_id == id_a && p.is_online))
    })
    .await;

    // 200 KiB（複数 64 KiB チャンク）のテストファイルを作成
    let src_path = work_dir.join("payload_200k.bin");
    let mut payload = vec![0u8; 200 * 1024 + 123];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xFF) as u8;
    }
    std::fs::write(&src_path, &payload).unwrap();

    // 1. Alice -> Bob へファイル送信要求
    node_a
        .cmd_tx
        .send(UiCommand::SendFile {
            peer_id: id_b.clone(),
            file_path: src_path.clone(),
        })
        .await
        .unwrap();

    let offer_id = match wait_for_event(&rx_b, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::FileOfferReceived { .. })
    })
    .await
    {
        AppEvent::FileOfferReceived {
            transfer_id,
            peer_id,
            filename,
            file_size,
            ..
        } => {
            assert_eq!(peer_id, id_a);
            assert_eq!(filename, "payload_200k.bin");
            assert_eq!(file_size, payload.len() as u64);
            transfer_id
        }
        _ => unreachable!(),
    };

    // Bob が承諾し保存先を指定
    let dest_path = work_dir.join("received_200k.bin");
    node_b
        .cmd_tx
        .send(UiCommand::RespondFileOffer {
            transfer_id: offer_id,
            accept: true,
            save_path: Some(dest_path.clone()),
        })
        .await
        .unwrap();

    // 双方の完了を待機
    match wait_for_event(&rx_a, Duration::from_secs(10), |e| {
        matches!(e, AppEvent::FileTransferFinished { .. })
    })
    .await
    {
        AppEvent::FileTransferFinished { ok, is_sending, .. } => {
            assert!(ok, "送信側が完了成功しませんでした");
            assert!(is_sending);
        }
        _ => unreachable!(),
    }
    match wait_for_event(&rx_b, Duration::from_secs(10), |e| {
        matches!(e, AppEvent::FileTransferFinished { .. })
    })
    .await
    {
        AppEvent::FileTransferFinished { ok, is_sending, .. } => {
            assert!(ok, "受信側が完了成功しませんでした");
            assert!(!is_sending);
        }
        _ => unreachable!(),
    }

    // 受信ファイルの内容一致と cache/ の完全消去を確認
    assert_eq!(std::fs::read(&dest_path).unwrap(), payload);
    assert!(
        !dir_b.join("cache").exists(),
        "受信完了後に cache/ が残っています"
    );

    // 2. 拒否フロー：Alice -> Bob へ再度送信要求、Bob が拒否
    node_a
        .cmd_tx
        .send(UiCommand::SendFile {
            peer_id: id_b.clone(),
            file_path: src_path,
        })
        .await
        .unwrap();

    let reject_offer_id = match wait_for_event(&rx_b, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::FileOfferReceived { .. })
    })
    .await
    {
        AppEvent::FileOfferReceived { transfer_id, .. } => transfer_id,
        _ => unreachable!(),
    };

    node_b
        .cmd_tx
        .send(UiCommand::RespondFileOffer {
            transfer_id: reject_offer_id,
            accept: false,
            save_path: None,
        })
        .await
        .unwrap();

    match wait_for_event(&rx_a, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::FileTransferFinished { .. })
    })
    .await
    {
        AppEvent::FileTransferFinished { ok, .. } => assert!(!ok),
        _ => unreachable!(),
    }

    node_a.cmd_tx.send(UiCommand::Shutdown).await.unwrap();
    node_b.cmd_tx.send(UiCommand::Shutdown).await.unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::ShutdownReady)
    })
    .await;
    wait_for_event(&rx_b, Duration::from_secs(5), |e| {
        matches!(e, AppEvent::ShutdownReady)
    })
    .await;
    let _ = node_a.join_handle.await;
    let _ = node_b.join_handle.await;

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&work_dir);
}
