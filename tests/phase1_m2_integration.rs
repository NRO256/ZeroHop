use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use zeroize::Zeroizing;

use zerohop::app::coordinator::{AppHandle, CoordinatorOptions, spawn_coordinator};
use zerohop::app::state::{AppEvent, UiCommand};
use zerohop::crypto::kdf::{Argon2Params, derive_session_keys_with_params};
use zerohop::domain::model::{DeliveryState, ThreadKey, UserStatus};
use zerohop::domain::protocol::{
    TcpPayload, UdpPayload, encode_tcp_control_frame, encode_udp_frame,
};
use zerohop::network::current_unix_timestamp;
use zerohop::network::tcp_transport::{read_tcp_control_frame, send_tcp_control_frame};
use zerohop::storage::cache_wipe::wipe_cache_dir;
use zerohop::storage::paths::AppPaths;

static INTEG_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_base_dir(name: &str) -> PathBuf {
    let seq = INTEG_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("zhop_integ_{name}_{}_{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fast_argon2() -> Argon2Params {
    Argon2Params {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    }
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
                    panic!("AppEvent channel disconnected before expected event; seen={seen:?}");
                }
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for expected AppEvent; seen={seen:?}");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn spawn_test_node(options: CoordinatorOptions) -> (AppHandle, Receiver<AppEvent>) {
    let (tx, rx) = mpsc::channel();
    let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let handle = spawn_coordinator(options, tx, wake);
    (handle, rx)
}

async fn login_node(
    handle: &AppHandle,
    rx: &Receiver<AppEvent>,
    name: &str,
    password: &str,
) -> (String, String, u16, u16) {
    handle
        .cmd_tx
        .send(UiCommand::LoginRequest {
            display_name: name.to_string(),
            password: Zeroizing::new(password.to_string()),
        })
        .await
        .unwrap();

    match wait_for_event(rx, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::LoginSucceeded { .. } | AppEvent::LoginFailed { .. }
        )
    })
    .await
    {
        AppEvent::LoginSucceeded {
            room_code,
            ephemeral_peer_id,
            tcp_port,
            udp_port,
            ..
        } => (room_code, ephemeral_peer_id, tcp_port, udp_port),
        AppEvent::LoginFailed { reason } => panic!("login failed unexpectedly: {reason}"),
        _ => unreachable!(),
    }
}

async fn shutdown_node(handle: AppHandle, rx: &Receiver<AppEvent>) {
    let _ = handle.cmd_tx.send(UiCommand::Shutdown).await;
    let _ = wait_for_event(rx, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ShutdownReady)
    })
    .await;
    handle.join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_peer_hello_direct_ack_and_broadcast_selective_retry() {
    let dir_a = temp_base_dir("m2_a");
    let dir_b = temp_base_dir("m2_b");

    let (alice, rx_a) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir_a.clone()),
    ));
    let (bob, rx_b) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir_b.clone()),
    ));

    let password = "SharedRoomPassword#1";
    let (code_a, alice_id, alice_tcp_port, _) = login_node(&alice, &rx_a, "Alice", password).await;
    let (code_b, bob_id, bob_tcp_port, _) = login_node(&bob, &rx_b, "Bob", password).await;
    assert_eq!(code_a, code_b);

    // 1. Alice が Bob を手動ピア追加 -> Hello 交換で正式 peer_id 統合
    alice
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: bob_tcp_port,
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::PeerListChanged(list)
                if list.iter().any(|p| p.peer_id == bob_id && p.display_name == "Bob")
        )
    })
    .await;
    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::PeerListChanged(list)
                if list.iter().any(|p| p.peer_id == alice_id && p.display_name == "Alice")
        )
    })
    .await;

    // 2. 1対1 チャット送受信と DirectDelivered 遷移
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Peer(bob_id.clone()),
            body: Zeroizing::new("1対1の暗号化メッセージ".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();

    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::ThreadUpdated { thread: ThreadKey::Peer(pid), new_count, .. }
                if pid == &alice_id && *new_count == 1
        )
    })
    .await;
    let received_direct = bob
        .log_reader
        .with_message(&ThreadKey::Peer(alice_id.clone()), 0, |m| m.body.clone())
        .unwrap();
    assert_eq!(received_direct, "1対1の暗号化メッセージ");

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        if let AppEvent::DeliveryUpdated {
            thread: ThreadKey::Peer(pid),
            ..
        } = ev
            && pid == &bob_id
        {
            return alice
                .log_reader
                .with_message(&ThreadKey::Peer(bob_id.clone()), 0, |m| {
                    m.delivery == DeliveryState::DirectDelivered
                })
                .unwrap_or(false);
        }
        false
    })
    .await;

    // 3. 全体チャット用の 3台目 Carol（一時的にオフライン切断をシミュレート可能なモック TCP ピア）を登録
    let room_keys = derive_session_keys_with_params(password, fast_argon2()).unwrap();
    let msg_key = room_keys.with_msg_key(|k| Zeroizing::new(*k)).unwrap();
    let carol_id = "carol-fixed-peer-id".to_string();
    let carol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let carol_port = carol_listener.local_addr().unwrap().port();

    // Carol から Alice へ Hello を送り、Alice 側へオンライン登録した後で Carol のリスナーを閉じる（通信瞬断状態）
    send_tcp_control_frame(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), alice_tcp_port),
        &msg_key,
        &TcpPayload::Hello {
            sender_id: carol_id.clone(),
            sender_name: "Carol".to_string(),
            tcp_port: carol_port,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 1,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .await
    .unwrap();
    // Alice が Hello 返信を試みる1回目を受理して閉じる
    if let Ok(Ok((mut s, _))) =
        tokio::time::timeout(Duration::from_secs(2), carol_listener.accept()).await
    {
        let _ = read_tcp_control_frame(&mut s, &msg_key).await;
    }
    drop(carol_listener);

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::PeerListChanged(list) if list.iter().any(|p| p.peer_id == carol_id)
        )
    })
    .await;

    // 4. Alice が全体チャットを送信 -> Bob は Ack、Carol は接続失敗 -> 一部未達 (1/2)
    alice
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Broadcast,
            body: Zeroizing::new("全体チャット集合Ackテスト".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();

    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::ThreadUpdated {
                thread: ThreadKey::Broadcast,
                new_count: 1,
                ..
            }
        )
    })
    .await;

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::DeliveryUpdated {
                thread: ThreadKey::Broadcast,
                ..
            }
        ) && alice
            .log_reader
            .with_message(&ThreadKey::Broadcast, 0, |m| {
                matches!(
                    &m.delivery,
                    DeliveryState::Broadcast {
                        target_count: 2,
                        acked_peers,
                        failed_peers,
                    } if acked_peers.contains(&bob_id) && failed_peers.contains(&carol_id)
                )
            })
            .unwrap_or(false)
    })
    .await;

    let bc_msg_id = alice
        .log_reader
        .with_message(&ThreadKey::Broadcast, 0, |m| {
            assert_eq!(m.delivery.status_label(), "一部未達 (1/2)");
            m.message_id.clone()
        })
        .unwrap();

    // 5. Carol 側のポートを復旧して再リスンさせ、未達相手のみ限定再送（RetryChat）
    let carol_recovered =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), carol_port))
            .await
            .unwrap();
    let msg_key_clone = msg_key.clone();
    let carol_id_clone = carol_id.clone();
    let alice_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), alice_tcp_port);
    let carol_task = tokio::spawn(async move {
        let (mut stream, _) = carol_recovered.accept().await.unwrap();
        let payload = read_tcp_control_frame(&mut stream, &msg_key_clone)
            .await
            .unwrap();
        let TcpPayload::Chat {
            message_id,
            is_broadcast,
            body,
            ..
        } = &payload
        else {
            panic!("expected Chat payload, got {payload:?}");
        };
        assert!(*is_broadcast);
        assert_eq!(body, "全体チャット集合Ackテスト");

        send_tcp_control_frame(
            alice_addr,
            &msg_key_clone,
            &TcpPayload::Ack {
                message_id: message_id.clone(),
                receiver_id: carol_id_clone,
                timestamp: current_unix_timestamp(),
            },
        )
        .await
        .unwrap();
    });

    alice
        .cmd_tx
        .send(UiCommand::RetryChat {
            thread: ThreadKey::Broadcast,
            message_id: bc_msg_id.clone(),
        })
        .await
        .unwrap();

    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::DeliveryUpdated {
                thread: ThreadKey::Broadcast,
                ..
            }
        ) && alice
            .log_reader
            .with_message(&ThreadKey::Broadcast, 0, |m| {
                m.delivery.status_label() == "全員到達 (2/2)"
            })
            .unwrap_or(false)
    })
    .await;
    carol_task.await.unwrap();

    // Bob 側の全体チャットは 1件のまま増えていないこと（重複送信・重複保存なし）
    assert_eq!(bob.log_reader.thread_len(&ThreadKey::Broadcast), 1);

    shutdown_node(alice, &rx_a).await;
    shutdown_node(bob, &rx_b).await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_and_tampered_packets_are_rejected_and_anomalies_rate_limited() {
    let dir1 = temp_base_dir("m2_sec1");
    let dir2 = temp_base_dir("m2_sec2");
    let dir3 = temp_base_dir("m2_sec3");

    let room_pass = "RoomAlpha#2026";
    let wrong_pass = "WrongRoom#2026";
    let same_keys = derive_session_keys_with_params(room_pass, fast_argon2()).unwrap();
    let wrong_keys = derive_session_keys_with_params(wrong_pass, fast_argon2()).unwrap();
    let same_msg_key = same_keys.with_msg_key(|k| Zeroizing::new(*k)).unwrap();
    let wrong_msg_key = wrong_keys.with_msg_key(|k| Zeroizing::new(*k)).unwrap();
    let wrong_beacon_key = wrong_keys.with_beacon_key(|k| Zeroizing::new(*k)).unwrap();

    // Node 1: 無認証 UDP・別鍵 UDP/TCP・偽 Ack 破棄 ＋ 同一 IP レート制限検証
    let (node1, rx1) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir1.clone()),
    ));
    let (_, _, n1_tcp, n1_udp) = login_node(&node1, &rx1, "Node1", room_pass).await;

    let udp_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let n1_udp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), n1_udp);
    let n1_tcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), n1_tcp);

    // 無認証生バイト列 UDP & 別鍵 Beacon & 偽 Bye
    udp_sender
        .send_to(b"UNAUTHENTICATED_GARBAGE", n1_udp_addr)
        .await
        .unwrap();
    let fake_beacon = encode_udp_frame(
        &wrong_beacon_key,
        &UdpPayload::Beacon {
            peer_id: "fake-peer".to_string(),
            display_name: "Attacker".to_string(),
            tcp_port: 45101,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 1,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .unwrap();
    udp_sender.send_to(&fake_beacon, n1_udp_addr).await.unwrap();

    // 1回目の KeyMismatchDetected が通知される
    wait_for_event(&rx1, Duration::from_secs(3), |ev| {
        matches!(ev, AppEvent::KeyMismatchDetected { .. })
    })
    .await;

    // 続けて別鍵 TCP / 改ざん AAD / 偽 Ack を連投してもレート制限により重複通知されず、状態も無傷
    let fake_ack = TcpPayload::Ack {
        message_id: "nonexistent".to_string(),
        receiver_id: "fake-peer".to_string(),
        timestamp: current_unix_timestamp(),
    };
    for _ in 0..4 {
        send_tcp_control_frame(n1_tcp_addr, &wrong_msg_key, &fake_ack)
            .await
            .unwrap();
    }
    let mut bad_aad = encode_tcp_control_frame(&same_msg_key, &fake_ack).unwrap();
    bad_aad[7] = 0xAA; // reserved バイト改ざん -> AAD/preamble 不正で破棄
    let mut raw_stream = tokio::net::TcpStream::connect(n1_tcp_addr).await.unwrap();
    raw_stream.write_all(&bad_aad).await.unwrap();
    drop(raw_stream);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let drained: Vec<AppEvent> = rx1.try_iter().collect();
    assert!(
        !drained
            .iter()
            .any(|ev| matches!(ev, AppEvent::KeyMismatchDetected { .. })),
        "rate limiter should suppress repeat KeyMismatch from same IP: {drained:?}"
    );
    assert!(!drained.iter().any(|ev| matches!(
        ev,
        AppEvent::PeerListChanged(_) | AppEvent::ThreadUpdated { .. }
    )));
    assert_eq!(node1.log_reader.total_bytes(), 0);

    // Node 2: 時計ズレ (+600秒) 通知の切り分け検証
    let (node2, rx2) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir2.clone()),
    ));
    let (_, _, n2_tcp, _) = login_node(&node2, &rx2, "Node2", room_pass).await;
    let skewed_chat = TcpPayload::Chat {
        message_id: "skew-1".to_string(),
        sender_id: "skew-sender".to_string(),
        sender_name: "SkewPeer".to_string(),
        is_broadcast: true,
        body: "未来時刻メッセージ".to_string(),
        timestamp: current_unix_timestamp() + 600,
        reply_to_id: None,
        reply_to_sender: None,
        reply_to_preview: None,
    };
    send_tcp_control_frame(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), n2_tcp),
        &same_msg_key,
        &skewed_chat,
    )
    .await
    .unwrap();
    match wait_for_event(&rx2, Duration::from_secs(3), |ev| {
        matches!(ev, AppEvent::ClockSkewDetected { .. })
    })
    .await
    {
        AppEvent::ClockSkewDetected { skew_seconds, .. } => {
            assert!(skew_seconds >= 590);
        }
        other => panic!("expected ClockSkewDetected, got {other:?}"),
    }
    assert_eq!(node2.log_reader.thread_len(&ThreadKey::Broadcast), 0);

    // Node 3: バージョン不一致 (v3) 通知の切り分け検証
    let (node3, rx3) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir3.clone()),
    ));
    let (_, _, n3_tcp, _) = login_node(&node3, &rx3, "Node3", room_pass).await;
    let mut ver3_frame = encode_tcp_control_frame(&same_msg_key, &fake_ack).unwrap();
    ver3_frame[4] = 0;
    ver3_frame[5] = 3; // version = 3
    let mut s3 =
        tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), n3_tcp))
            .await
            .unwrap();
    s3.write_all(&ver3_frame).await.unwrap();
    drop(s3);
    assert_eq!(
        wait_for_event(&rx3, Duration::from_secs(3), |ev| {
            matches!(ev, AppEvent::ProtocolVersionMismatch { .. })
        })
        .await,
        AppEvent::ProtocolVersionMismatch {
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_version: 3,
        }
    );

    shutdown_node(node1, &rx1).await;
    shutdown_node(node2, &rx2).await;
    shutdown_node(node3, &rx3).await;
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_dir_all(&dir3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypted_udp_discovery_and_bye_lifecycle() {
    let dir_a = temp_base_dir("m2_udp_a");
    let dir_b = temp_base_dir("m2_udp_b");
    let pass = "UdpDiscovery#2026";

    let (node_b, rx_b) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir_b.clone()),
    ));
    let (_, _, _, b_udp_port) = login_node(&node_b, &rx_b, "ReceiverB", pass).await;

    let mut opts_a = CoordinatorOptions::loopback_for_test(AppPaths::from_base_dir(dir_a.clone()));
    opts_a.udp_target_override = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), b_udp_port));
    opts_a.beacon_interval = Duration::from_millis(100);
    let (node_a, rx_a) = spawn_test_node(opts_a);
    let (_, a_peer_id, _, _) = login_node(&node_a, &rx_a, "BeaconA", pass).await;

    // 暗号化 UDP Beacon で Node B が Node A を自動検出
    wait_for_event(&rx_b, Duration::from_secs(5), |ev| {
        matches!(
            ev,
            AppEvent::PeerJoined { peer_id, display_name }
                if peer_id == &a_peer_id && display_name == "BeaconA"
        )
    })
    .await;

    // Node A ログアウト時の暗号化 Bye 2回送信により Node B で即オフライン除去（会話0件のため一覧からも削除）
    node_a.cmd_tx.send(UiCommand::Logout).await.unwrap();
    wait_for_event(&rx_a, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LogoutCompleted)
    })
    .await;

    wait_for_event(
        &rx_b,
        Duration::from_secs(5),
        |ev| matches!(ev, AppEvent::PeerListChanged(list) if list.is_empty()),
    )
    .await;

    shutdown_node(node_a, &rx_a).await;
    shutdown_node(node_b, &rx_b).await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_login_chat_logout_relogin_lifecycle() {
    let dir_main = temp_base_dir("m2_life_main");
    let dir_peer = temp_base_dir("m2_life_peer");

    let (main_node, rx_main) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir_main.clone()),
    ));
    let (peer_node, rx_peer) = spawn_test_node(CoordinatorOptions::loopback_for_test(
        AppPaths::from_base_dir(dir_peer.clone()),
    ));

    // セッション1
    let (code1, id1, _, _) = login_node(&main_node, &rx_main, "UserOne", "RoomPass1#2026").await;
    let (_, peer_id1, peer_tcp1, _) =
        login_node(&peer_node, &rx_peer, "Partner", "RoomPass1#2026").await;

    main_node
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: peer_tcp1,
        })
        .await
        .unwrap();
    wait_for_event(
        &rx_main,
        Duration::from_secs(5),
        |ev| matches!(ev, AppEvent::PeerListChanged(list) if list.iter().any(|p| p.peer_id == peer_id1)),
    )
    .await;

    main_node
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Peer(peer_id1.clone()),
            body: Zeroizing::new("セッション1の会話".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx_peer, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ThreadUpdated { .. })
    })
    .await;
    assert!(main_node.log_reader.total_bytes() > 0);

    // ログアウト -> 全消去
    main_node.cmd_tx.send(UiCommand::Logout).await.unwrap();
    wait_for_event(&rx_main, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LogoutCompleted)
    })
    .await;
    assert_eq!(main_node.log_reader.total_bytes(), 0);
    assert_eq!(
        main_node.log_reader.thread_len(&ThreadKey::Peer(peer_id1)),
        0
    );

    // パートナーも別ルームパスワードで再ログイン
    peer_node.cmd_tx.send(UiCommand::Logout).await.unwrap();
    wait_for_event(&rx_peer, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LogoutCompleted)
    })
    .await;

    // セッション2（異なる表示名・異なるパスワード・新規エフェメラル ID）
    let (code2, id2, _, _) = login_node(&main_node, &rx_main, "UserTwo", "RoomPass2#2026").await;
    let (_, peer_id2, peer_tcp2, _) =
        login_node(&peer_node, &rx_peer, "Partner2", "RoomPass2#2026").await;
    assert_ne!(id1, id2);
    assert_ne!(code1, code2);

    main_node
        .cmd_tx
        .send(UiCommand::AddManualPeer {
            host: "127.0.0.1".to_string(),
            tcp_port: peer_tcp2,
        })
        .await
        .unwrap();
    wait_for_event(
        &rx_main,
        Duration::from_secs(5),
        |ev| matches!(ev, AppEvent::PeerListChanged(list) if list.iter().any(|p| p.peer_id == peer_id2)),
    )
    .await;
    main_node
        .cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Peer(peer_id2),
            body: Zeroizing::new("セッション2の会話".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx_peer, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::ThreadUpdated { .. })
    })
    .await;

    shutdown_node(main_node, &rx_main).await;
    shutdown_node(peer_node, &rx_peer).await;
    let _ = std::fs::remove_dir_all(&dir_main);
    let _ = std::fs::remove_dir_all(&dir_peer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_persistence_leaves_no_files_and_cleans_residual_cache() {
    let dir = temp_base_dir("m2_zero_persist");
    let paths = AppPaths::from_base_dir(dir.clone());

    // 事前残骸 cache/transfers/leftover.enc を配置して起動時掃除を模擬
    std::fs::create_dir_all(paths.transfers_dir()).unwrap();
    std::fs::write(paths.transfers_dir().join("leftover.enc"), b"leftover").unwrap();
    let wipe_report = wipe_cache_dir(&paths).unwrap();
    assert!(wipe_report.existed);
    assert!(!paths.cache_dir().exists());

    let (node, rx) = spawn_test_node(CoordinatorOptions::loopback_for_test(paths.clone()));
    let _ = login_node(&node, &rx, "SecretUserYamada", "UltraSecretPass!99").await;

    node.cmd_tx
        .send(UiCommand::SendChat {
            thread: ThreadKey::Broadcast,
            body: Zeroizing::new("極秘の会話メッセージXYZ".to_string()),
            reply_to: None,
        })
        .await
        .unwrap();
    wait_for_event(&rx, Duration::from_secs(3), |ev| {
        matches!(
            ev,
            AppEvent::ThreadUpdated {
                thread: ThreadKey::Broadcast,
                new_count: 1,
                ..
            }
        )
    })
    .await;

    node.cmd_tx
        .send(UiCommand::ClearSessionChat { thread: None })
        .await
        .unwrap();
    wait_for_event(&rx, Duration::from_secs(3), |ev| {
        matches!(
            ev,
            AppEvent::ThreadUpdated {
                thread: ThreadKey::Broadcast,
                new_count: 0,
                ..
            }
        )
    })
    .await;

    node.cmd_tx.send(UiCommand::Logout).await.unwrap();
    wait_for_event(&rx, Duration::from_secs(5), |ev| {
        matches!(ev, AppEvent::LogoutCompleted)
    })
    .await;
    shutdown_node(node, &rx).await;

    // ディスク上にファイルもディレクトリも一切残っていないこと
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(
        entries.is_empty(),
        "expected zero files under base_dir, found {entries:?}"
    );
    assert!(!paths.cache_dir().exists());
    assert!(!paths.config_path().exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sec001_sec005_blocks_reflection_replay_manual_promotion_and_sanitizes_chat() {
    let dir = temp_base_dir("m3_sec_hardening");
    let mut opts = CoordinatorOptions::loopback_for_test(AppPaths::from_base_dir(dir.clone()));
    opts.peer_timeout_secs = 2;
    let pass = "SecurityRoom#2026";
    let (victim, rx_v) = spawn_test_node(opts);
    let (_, _, v_tcp_port, v_udp_port) = login_node(&victim, &rx_v, "Victim", pass).await;

    let keys = derive_session_keys_with_params(pass, fast_argon2()).unwrap();
    let msg_key = keys.with_msg_key(|k| Zeroizing::new(*k)).unwrap();
    let beacon_key = keys.with_beacon_key(|k| Zeroizing::new(*k)).unwrap();

    let v_udp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v_udp_port);
    let v_tcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v_tcp_port);
    let attacker_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. 正規 peer (192.168.10.50 を advertised_ip として持つ) の Beacon / Hello を別 IP (127.0.0.1) から反射 -> 拒否
    let spoofed_beacon = encode_udp_frame(
        &beacon_key,
        &UdpPayload::Beacon {
            peer_id: "legit-peer-1".to_string(),
            display_name: "Legit".to_string(),
            tcp_port: 45111,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 1,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 50))),
        },
    )
    .unwrap();
    attacker_udp
        .send_to(&spoofed_beacon, v_udp_addr)
        .await
        .unwrap();

    send_tcp_control_frame(
        v_tcp_addr,
        &msg_key,
        &TcpPayload::Hello {
            sender_id: "legit-peer-1".to_string(),
            sender_name: "Legit".to_string(),
            tcp_port: 45111,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 1,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 50))),
        },
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen_before: Vec<AppEvent> = rx_v.try_iter().collect();
    assert!(
        !seen_before
            .iter()
            .any(|ev| matches!(ev, AppEvent::PeerJoined { .. })),
        "reflected Beacon/Hello with mismatched advertised_ip must be rejected: {seen_before:?}"
    );

    // 2. 正常な Beacon (seq=10) -> Bye (seq=11) の直後に過去 Beacon (seq=10) をリプレイしてもゴースト復活しないこと
    let replay_beacon_10 = encode_udp_frame(
        &beacon_key,
        &UdpPayload::Beacon {
            peer_id: "legit-peer-1".to_string(),
            display_name: "Legit".to_string(),
            tcp_port: 45111,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 10,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .unwrap();
    attacker_udp
        .send_to(&replay_beacon_10, v_udp_addr)
        .await
        .unwrap();
    wait_for_event(
        &rx_v,
        Duration::from_secs(3),
        |ev| matches!(ev, AppEvent::PeerJoined { peer_id, .. } if peer_id == "legit-peer-1"),
    )
    .await;

    let bye_11 = encode_udp_frame(
        &beacon_key,
        &UdpPayload::Bye {
            peer_id: "legit-peer-1".to_string(),
            timestamp: current_unix_timestamp(),
            seq: 11,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .unwrap();
    attacker_udp.send_to(&bye_11, v_udp_addr).await.unwrap();
    wait_for_event(
        &rx_v,
        Duration::from_secs(3),
        |ev| matches!(ev, AppEvent::PeerListChanged(list) if list.is_empty()),
    )
    .await;

    attacker_udp
        .send_to(&replay_beacon_10, v_udp_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after_replay: Vec<AppEvent> = rx_v.try_iter().collect();
    assert!(
        !after_replay
            .iter()
            .any(|ev| matches!(ev, AppEvent::PeerJoined { .. })),
        "replayed Beacon(seq=10) after Bye(seq=11) must be ignored: {after_replay:?}"
    );

    // 3. Discovered ピア (seq=12) に対し unsolicited Hello (seq=1) を送っても Manual 永続昇格せず、2秒タイムアウトで除去される
    let beacon_12 = encode_udp_frame(
        &beacon_key,
        &UdpPayload::Beacon {
            peer_id: "legit-peer-1".to_string(),
            display_name: "Legit".to_string(),
            tcp_port: 45111,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 12,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .unwrap();
    attacker_udp.send_to(&beacon_12, v_udp_addr).await.unwrap();
    wait_for_event(
        &rx_v,
        Duration::from_secs(3),
        |ev| matches!(ev, AppEvent::PeerJoined { peer_id, .. } if peer_id == "legit-peer-1"),
    )
    .await;

    send_tcp_control_frame(
        v_tcp_addr,
        &msg_key,
        &TcpPayload::Hello {
            sender_id: "legit-peer-1".to_string(),
            sender_name: "Legit".to_string(),
            tcp_port: 45111,
            status: UserStatus::Online,
            timestamp: current_unix_timestamp(),
            seq: 1,
            advertised_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        },
    )
    .await
    .unwrap();

    // peer_timeout_secs = 2 秒＋スウィープ間隔 1 秒以内に Discovered としてオフライン除去される
    wait_for_event(
        &rx_v,
        Duration::from_secs(5),
        |ev| matches!(ev, AppEvent::PeerListChanged(list) if list.is_empty()),
    )
    .await;

    // 4. SEC-005: 65バイト超 message_id / sender_id は拒否され、正常IDの Chat 本文は制御文字サニタイズされる
    send_tcp_control_frame(
        v_tcp_addr,
        &msg_key,
        &TcpPayload::Chat {
            message_id: "x".repeat(65),
            sender_id: "legit-peer-2".to_string(),
            sender_name: "Legit2".to_string(),
            is_broadcast: true,
            body: "拒否されるべき長大ID".to_string(),
            timestamp: current_unix_timestamp(),
            reply_to_id: None,
            reply_to_sender: None,
            reply_to_preview: None,
        },
    )
    .await
    .unwrap();

    send_tcp_control_frame(
        v_tcp_addr,
        &msg_key,
        &TcpPayload::Chat {
            message_id: "msg-clean-1".to_string(),
            sender_id: "legit-peer-2".to_string(),
            sender_name: "Legit2".to_string(),
            is_broadcast: true,
            body: "安全\r\n本文\x00\x1b[31mOK".to_string(),
            timestamp: current_unix_timestamp(),
            reply_to_id: None,
            reply_to_sender: None,
            reply_to_preview: None,
        },
    )
    .await
    .unwrap();

    wait_for_event(&rx_v, Duration::from_secs(3), |ev| {
        matches!(
            ev,
            AppEvent::ThreadUpdated {
                thread: ThreadKey::Broadcast,
                new_count: 1,
                ..
            }
        )
    })
    .await;
    assert_eq!(victim.log_reader.thread_len(&ThreadKey::Broadcast), 1);
    let stored = victim
        .log_reader
        .with_message(&ThreadKey::Broadcast, 0, |m| {
            (m.message_id.clone(), m.body.clone())
        })
        .unwrap();
    assert_eq!(stored.0, "msg-clean-1");
    assert_eq!(stored.1, "安全\n本文[31mOK");

    shutdown_node(victim, &rx_v).await;
    let _ = std::fs::remove_dir_all(&dir);
}
