use std::collections::{HashMap, VecDeque};

use zeroize::Zeroize;

use crate::domain::model::{InMemoryChatMessage, MAX_MESSAGES_PER_THREAD, ThreadKey};
use crate::domain::validation::{ValidationError, validate_received_chat_body};

#[derive(Debug)]
struct StoredMessage {
    seq: u64,
    message: InMemoryChatMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushOutcome {
    pub evicted_from_thread: usize,
    pub evicted_for_budget: usize,
}

/// 4重メモリガード付き単一インメモリ会話ストア（Core 単一保持）
#[derive(Debug)]
pub struct SessionLog {
    max_total_bytes: usize,
    current_total_bytes: usize,
    max_messages_per_thread: usize,
    next_seq: u64,
    threads: HashMap<ThreadKey, VecDeque<StoredMessage>>,
}

impl SessionLog {
    pub fn new(max_total_bytes: usize) -> Self {
        Self::with_limits(max_total_bytes, MAX_MESSAGES_PER_THREAD)
    }

    pub fn with_limits(max_total_bytes: usize, max_messages_per_thread: usize) -> Self {
        Self {
            max_total_bytes,
            current_total_bytes: 0,
            max_messages_per_thread: max_messages_per_thread.max(1),
            next_seq: 1,
            threads: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn clone_empty_for_test(&self) -> Self {
        Self::with_limits(self.max_total_bytes, self.max_messages_per_thread)
    }

    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    pub fn current_total_bytes(&self) -> usize {
        self.current_total_bytes
    }

    pub fn total_message_count(&self) -> usize {
        self.threads.values().map(VecDeque::len).sum()
    }

    pub fn thread_len(&self, thread: &ThreadKey) -> usize {
        self.threads.get(thread).map_or(0, VecDeque::len)
    }

    pub fn get_message(&self, thread: &ThreadKey, index: usize) -> Option<&InMemoryChatMessage> {
        self.threads
            .get(thread)
            .and_then(|queue| queue.get(index))
            .map(|stored| &stored.message)
    }

    pub fn push_message(
        &mut self,
        thread: ThreadKey,
        mut msg: InMemoryChatMessage,
    ) -> Result<PushOutcome, ValidationError> {
        validate_received_chat_body(&msg.body)?;
        msg.approx_bytes = msg.compute_approx_bytes();

        let mut evicted_from_thread = 0usize;
        {
            let queue = self.threads.entry(thread).or_default();
            while queue.len() >= self.max_messages_per_thread {
                if let Some(mut oldest) = queue.pop_front() {
                    self.current_total_bytes = self
                        .current_total_bytes
                        .saturating_sub(oldest.message.approx_bytes);
                    oldest.message.zeroize();
                    evicted_from_thread += 1;
                }
            }
            let seq = self.next_seq;
            self.next_seq = self.next_seq.saturating_add(1);
            self.current_total_bytes = self.current_total_bytes.saturating_add(msg.approx_bytes);
            queue.push_back(StoredMessage { seq, message: msg });
        }

        let evicted_for_budget = self.enforce_total_budget();
        Ok(PushOutcome {
            evicted_from_thread,
            evicted_for_budget,
        })
    }

    pub fn set_max_total_bytes(&mut self, new_limit: usize) -> usize {
        self.max_total_bytes = new_limit;
        self.enforce_total_budget()
    }

    fn enforce_total_budget(&mut self) -> usize {
        let mut evicted = 0usize;
        while self.current_total_bytes > self.max_total_bytes {
            let oldest_key = self
                .threads
                .iter()
                .filter_map(|(k, q)| q.front().map(|front| (front.seq, k.clone())))
                .min_by_key(|(seq, _)| *seq)
                .map(|(_, k)| k);

            let Some(key) = oldest_key else {
                self.current_total_bytes = 0;
                break;
            };

            let remove_empty = if let Some(queue) = self.threads.get_mut(&key) {
                if let Some(mut oldest) = queue.pop_front() {
                    self.current_total_bytes = self
                        .current_total_bytes
                        .saturating_sub(oldest.message.approx_bytes);
                    oldest.message.zeroize();
                    evicted += 1;
                }
                queue.is_empty()
            } else {
                false
            };

            if remove_empty {
                self.threads.remove(&key);
            }
        }
        evicted
    }

    pub fn update_delivery_ack(
        &mut self,
        thread: &ThreadKey,
        message_id: &str,
        receiver_id: &str,
    ) -> bool {
        let delta = {
            let Some(queue) = self.threads.get_mut(thread) else {
                return false;
            };
            let Some(stored) = queue
                .iter_mut()
                .rev()
                .find(|entry| entry.message.message_id == message_id)
            else {
                return false;
            };
            if !stored.message.delivery.record_ack(receiver_id) {
                return false;
            }
            stored.message.recalculate_approx_bytes()
        };
        self.apply_byte_delta(delta);
        true
    }

    pub fn mark_delivery_failed(
        &mut self,
        thread: &ThreadKey,
        message_id: &str,
        peer_id: Option<&str>,
    ) -> bool {
        let delta = {
            let Some(queue) = self.threads.get_mut(thread) else {
                return false;
            };
            let Some(stored) = queue
                .iter_mut()
                .rev()
                .find(|entry| entry.message.message_id == message_id)
            else {
                return false;
            };
            if !stored.message.delivery.mark_failed(peer_id) {
                return false;
            }
            stored.message.recalculate_approx_bytes()
        };
        self.apply_byte_delta(delta);
        true
    }

    fn apply_byte_delta(&mut self, delta: isize) {
        if delta >= 0 {
            self.current_total_bytes = self.current_total_bytes.saturating_add(delta as usize);
            let _ = self.enforce_total_budget();
        } else {
            self.current_total_bytes = self
                .current_total_bytes
                .saturating_sub(delta.unsigned_abs());
        }
    }

    pub fn clear_thread(&mut self, thread: &ThreadKey) -> usize {
        self.remove_thread(thread)
    }

    pub fn remove_thread(&mut self, thread: &ThreadKey) -> usize {
        let Some(mut queue) = self.threads.remove(thread) else {
            return 0;
        };
        let count = queue.len();
        while let Some(mut stored) = queue.pop_front() {
            self.current_total_bytes = self
                .current_total_bytes
                .saturating_sub(stored.message.approx_bytes);
            stored.message.zeroize();
        }
        count
    }

    pub fn merge_peer_thread(&mut self, from_peer_id: &str, to_peer_id: &str) -> usize {
        if from_peer_id == to_peer_id {
            return 0;
        }
        let from_key = ThreadKey::Peer(from_peer_id.to_string());
        let Some(mut from_queue) = self.threads.remove(&from_key) else {
            return 0;
        };
        let moved_total = from_queue.len();
        let to_key = ThreadKey::Peer(to_peer_id.to_string());
        let to_queue = self.threads.entry(to_key).or_default();

        let mut merged: Vec<StoredMessage> = Vec::with_capacity(to_queue.len() + from_queue.len());
        merged.extend(to_queue.drain(..));
        merged.extend(from_queue.drain(..));
        merged.sort_by_key(|item| item.seq);

        while merged.len() > self.max_messages_per_thread {
            let mut dropped = merged.remove(0);
            self.current_total_bytes = self
                .current_total_bytes
                .saturating_sub(dropped.message.approx_bytes);
            dropped.message.zeroize();
        }
        to_queue.extend(merged);
        let _ = self.enforce_total_budget();
        moved_total
    }

    pub fn clear_all(&mut self) -> usize {
        let mut count = 0usize;
        for (_, mut queue) in self.threads.drain() {
            while let Some(mut stored) = queue.pop_front() {
                stored.message.zeroize();
                count += 1;
            }
        }
        self.current_total_bytes = 0;
        count
    }
}

impl Drop for SessionLog {
    fn drop(&mut self) {
        let _ = self.clear_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::model::DeliveryState;

    fn make_msg(id: &str, body: &str, ts: i64) -> InMemoryChatMessage {
        InMemoryChatMessage::new(id, "sender-1", "Alice", body, ts, DeliveryState::Received)
    }

    #[test]
    fn rejects_body_exceeding_4kib() {
        let mut log = SessionLog::new(64 * 1024);
        let oversized = make_msg("m1", &"a".repeat(4097), 100);
        let err = log
            .push_message(ThreadKey::Broadcast, oversized)
            .unwrap_err();
        assert_eq!(
            err,
            ValidationError::ChatBodyTooLong {
                max_bytes: 4096,
                actual_bytes: 4097
            }
        );
        assert_eq!(log.total_message_count(), 0);
        assert_eq!(log.current_total_bytes(), 0);
    }

    #[test]
    fn enforces_per_thread_1000_message_limit() {
        let mut log = SessionLog::new(16 * 1024 * 1024);
        for i in 0..1005 {
            let msg = make_msg(&format!("id-{i}"), &format!("body-{i}"), 1000 + i as i64);
            log.push_message(ThreadKey::Broadcast, msg).unwrap();
        }

        assert_eq!(log.thread_len(&ThreadKey::Broadcast), 1000);
        assert_eq!(
            log.get_message(&ThreadKey::Broadcast, 0)
                .unwrap()
                .message_id,
            "id-5"
        );
        assert_eq!(
            log.get_message(&ThreadKey::Broadcast, 999)
                .unwrap()
                .message_id,
            "id-1004"
        );
    }

    #[test]
    fn enforces_total_byte_budget_by_evicting_oldest_across_threads() {
        // 縮小上限 16 KiB で 4 KiB 近い長文を異なるスレッドへ連続投入
        let budget = 16 * 1024;
        let mut log = SessionLog::new(budget);
        let payload = "x".repeat(3800);

        for i in 0..10 {
            let thread = if i % 2 == 0 {
                ThreadKey::Broadcast
            } else {
                ThreadKey::Peer("peer-1".to_string())
            };
            let msg = make_msg(&format!("msg-{i}"), &payload, 1000 + i as i64);
            log.push_message(thread, msg).unwrap();
            assert!(log.current_total_bytes() <= budget);
        }

        assert!(log.current_total_bytes() <= budget);
        assert!(log.total_message_count() <= 4);

        // 最古系列は消え、最新メッセージは各スレッドに残っている
        let latest_bc = log
            .get_message(
                &ThreadKey::Broadcast,
                log.thread_len(&ThreadKey::Broadcast) - 1,
            )
            .unwrap();
        assert_eq!(latest_bc.message_id, "msg-8");

        let latest_p1 = log
            .get_message(
                &ThreadKey::Peer("peer-1".to_string()),
                log.thread_len(&ThreadKey::Peer("peer-1".to_string())) - 1,
            )
            .unwrap();
        assert_eq!(latest_p1.message_id, "msg-9");
    }

    #[test]
    fn clear_thread_and_clear_all_reclaim_bytes_and_counts() {
        let mut log = SessionLog::new(1024 * 1024);
        log.push_message(ThreadKey::Broadcast, make_msg("b1", "全体1", 10))
            .unwrap();
        log.push_message(
            ThreadKey::Peer("p1".to_string()),
            make_msg("p1-1", "個別1", 11),
        )
        .unwrap();

        assert!(log.current_total_bytes() > 0);
        assert_eq!(log.clear_thread(&ThreadKey::Broadcast), 1);
        assert_eq!(log.thread_len(&ThreadKey::Broadcast), 0);
        assert_eq!(log.total_message_count(), 1);

        assert_eq!(log.clear_all(), 1);
        assert_eq!(log.total_message_count(), 0);
        assert_eq!(log.current_total_bytes(), 0);
    }

    #[test]
    fn ack_updates_delivery_state_and_adjusts_budget() {
        let mut log = SessionLog::new(1024 * 1024);
        let msg = InMemoryChatMessage::new(
            "bc-1",
            "me",
            "Me",
            "全員へ連絡",
            200,
            DeliveryState::new_broadcast(2),
        );
        log.push_message(ThreadKey::Broadcast, msg).unwrap();
        let initial_bytes = log.current_total_bytes();

        assert!(log.update_delivery_ack(&ThreadKey::Broadcast, "bc-1", "peer-a"));
        assert!(log.current_total_bytes() > initial_bytes);

        let updated = log.get_message(&ThreadKey::Broadcast, 0).unwrap();
        assert_eq!(updated.delivery.status_label(), "一部到達 (1/2)");

        assert!(log.update_delivery_ack(&ThreadKey::Broadcast, "bc-1", "peer-b"));
        let completed = log.get_message(&ThreadKey::Broadcast, 0).unwrap();
        assert_eq!(completed.delivery.status_label(), "全員到達 (2/2)");
    }

    #[test]
    fn message_zeroizes_fields_on_explicit_zeroize() {
        let mut msg = make_msg("id-secret", "秘密の会話内容", 123);
        msg.zeroize();
        assert!(msg.message_id.is_empty());
        assert!(msg.sender_id.is_empty());
        assert!(msg.sender_name.is_empty());
        assert!(msg.body.is_empty());
        assert_eq!(msg.timestamp, 0);
        assert_eq!(msg.approx_bytes, 0);
    }
}
