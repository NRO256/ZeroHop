use std::collections::{HashMap, HashSet, VecDeque};

use zeroize::Zeroize;

pub const DEFAULT_TIMESTAMP_WINDOW_SECS: i64 = 300; // ±5分
pub const DEFAULT_REPLAY_TTL_SECS: i64 = 600; // 10分
pub const DEFAULT_GLOBAL_REPLAY_LIMIT: usize = 10_000;
pub const DEFAULT_PER_SENDER_REPLAY_LIMIT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheckError {
    ClockSkew { skew_seconds: i64 },
    DuplicateMessage,
}

pub fn check_timestamp_window(
    msg_timestamp: i64,
    now_unix: i64,
    max_skew_secs: i64,
) -> Result<(), i64> {
    let skew = msg_timestamp.saturating_sub(now_unix);
    if skew.saturating_abs() > max_skew_secs {
        Err(skew)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
struct ReplayEntry {
    message_id: String,
    recorded_at: i64,
    seq: u64,
}

#[derive(Debug, Default)]
struct SenderBucket {
    order: VecDeque<ReplayEntry>,
    ids: HashSet<String>,
}

impl SenderBucket {
    fn contains(&self, message_id: &str) -> bool {
        self.ids.contains(message_id)
    }

    fn pop_oldest(&mut self) -> bool {
        let Some(mut oldest) = self.order.pop_front() else {
            return false;
        };
        self.ids.remove(&oldest.message_id);
        oldest.message_id.zeroize();
        true
    }

    fn purge_expired(&mut self, cutoff_unix: i64) -> usize {
        let mut removed = 0usize;
        while let Some(front) = self.order.front() {
            if front.recorded_at < cutoff_unix {
                if self.pop_oldest() {
                    removed += 1;
                }
            } else {
                break;
            }
        }
        removed
    }

    fn push(&mut self, message_id: String, recorded_at: i64, seq: u64) {
        self.ids.insert(message_id.clone());
        self.order.push_back(ReplayEntry {
            message_id,
            recorded_at,
            seq,
        });
    }

    fn clear(&mut self) {
        while let Some(mut entry) = self.order.pop_front() {
            entry.message_id.zeroize();
        }
        for mut id in self.ids.drain() {
            id.zeroize();
        }
    }
}

/// 二階層リプレイキャッシュ（全体上限 10,000件・送信者別上限 500件・保持 10分）
#[derive(Debug)]
pub struct ReplayCache {
    timestamp_window_secs: i64,
    ttl_secs: i64,
    global_limit: usize,
    per_sender_limit: usize,
    total_entries: usize,
    next_seq: u64,
    buckets: HashMap<String, SenderBucket>,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_TIMESTAMP_WINDOW_SECS,
            DEFAULT_REPLAY_TTL_SECS,
            DEFAULT_GLOBAL_REPLAY_LIMIT,
            DEFAULT_PER_SENDER_REPLAY_LIMIT,
        )
    }

    pub fn with_limits(
        timestamp_window_secs: i64,
        ttl_secs: i64,
        global_limit: usize,
        per_sender_limit: usize,
    ) -> Self {
        Self {
            timestamp_window_secs: timestamp_window_secs.max(0),
            ttl_secs: ttl_secs.max(0),
            global_limit: global_limit.max(1),
            per_sender_limit: per_sender_limit.max(1),
            total_entries: 0,
            next_seq: 1,
            buckets: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.total_entries
    }

    pub fn is_empty(&self) -> bool {
        self.total_entries == 0
    }

    pub fn sender_len(&self, sender_id: &str) -> usize {
        self.buckets.get(sender_id).map_or(0, |b| b.order.len())
    }

    pub fn check_and_record(
        &mut self,
        sender_id: &str,
        message_id: &str,
        msg_timestamp: i64,
        now_unix: i64,
    ) -> Result<(), ReplayCheckError> {
        check_timestamp_window(msg_timestamp, now_unix, self.timestamp_window_secs)
            .map_err(|skew_seconds| ReplayCheckError::ClockSkew { skew_seconds })?;

        self.purge_expired(now_unix);

        if self
            .buckets
            .get(sender_id)
            .is_some_and(|bucket| bucket.contains(message_id))
        {
            return Err(ReplayCheckError::DuplicateMessage);
        }

        if let Some(bucket) = self.buckets.get_mut(sender_id) {
            while bucket.order.len() >= self.per_sender_limit {
                if bucket.pop_oldest() {
                    self.total_entries = self.total_entries.saturating_sub(1);
                }
            }
        }

        while self.total_entries >= self.global_limit {
            if !self.evict_global_oldest() {
                break;
            }
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let bucket = self.buckets.entry(sender_id.to_string()).or_default();
        bucket.push(message_id.to_string(), now_unix, seq);
        self.total_entries = self.total_entries.saturating_add(1);

        Ok(())
    }

    pub fn purge_expired(&mut self, now_unix: i64) -> usize {
        let cutoff = now_unix.saturating_sub(self.ttl_secs);
        let mut removed_total = 0usize;
        let mut empty_keys = Vec::new();

        for (sender_id, bucket) in &mut self.buckets {
            let removed = bucket.purge_expired(cutoff);
            if removed > 0 {
                self.total_entries = self.total_entries.saturating_sub(removed);
                removed_total += removed;
            }
            if bucket.order.is_empty() {
                empty_keys.push(sender_id.clone());
            }
        }

        for mut key in empty_keys {
            if let Some(mut bucket) = self.buckets.remove(&key) {
                bucket.clear();
            }
            key.zeroize();
        }
        removed_total
    }

    fn evict_global_oldest(&mut self) -> bool {
        let oldest_sender = self
            .buckets
            .iter()
            .filter_map(|(sender, bucket)| {
                bucket
                    .order
                    .front()
                    .map(|front| ((front.recorded_at, front.seq), sender.clone()))
            })
            .min_by_key(|(order_key, _)| *order_key)
            .map(|(_, sender)| sender);

        let Some(sender_key) = oldest_sender else {
            self.total_entries = 0;
            return false;
        };

        let mut remove_bucket = false;
        let mut evicted = false;
        if let Some(bucket) = self.buckets.get_mut(&sender_key) {
            evicted = bucket.pop_oldest();
            if evicted {
                self.total_entries = self.total_entries.saturating_sub(1);
            }
            remove_bucket = bucket.order.is_empty();
        }
        if remove_bucket && let Some(mut bucket) = self.buckets.remove(&sender_key) {
            bucket.clear();
        }
        evicted
    }

    pub fn clear(&mut self) {
        for (mut sender_id, mut bucket) in self.buckets.drain() {
            bucket.clear();
            sender_id.zeroize();
        }
        self.total_entries = 0;
    }
}

impl Drop for ReplayCache {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_5min_timestamp_window_boundaries() {
        let mut cache = ReplayCache::new();
        let now = 1_700_000_000i64;

        // 境界 +300秒 / -300秒 は許可
        assert!(
            cache
                .check_and_record("s1", "m-plus", now + 300, now)
                .is_ok()
        );
        assert!(
            cache
                .check_and_record("s1", "m-minus", now - 300, now)
                .is_ok()
        );

        // +301秒 / -301秒 は ClockSkew（記録もされない）
        assert_eq!(
            cache.check_and_record("s1", "m-over", now + 301, now),
            Err(ReplayCheckError::ClockSkew { skew_seconds: 301 })
        );
        assert_eq!(
            cache.check_and_record("s1", "m-under", now - 301, now),
            Err(ReplayCheckError::ClockSkew { skew_seconds: -301 })
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn rejects_duplicate_message_per_sender() {
        let mut cache = ReplayCache::new();
        let now = 1_700_000_000i64;

        assert!(
            cache
                .check_and_record("sender-a", "msg-1", now, now)
                .is_ok()
        );
        assert_eq!(
            cache.check_and_record("sender-a", "msg-1", now, now + 1),
            Err(ReplayCheckError::DuplicateMessage)
        );
        // 別送信者の同じ message_id は独立して許可
        assert!(
            cache
                .check_and_record("sender-b", "msg-1", now, now + 1)
                .is_ok()
        );
    }

    #[test]
    fn single_sender_flood_does_not_evict_other_senders_and_caps_at_500() {
        let mut cache = ReplayCache::new();
        let now = 1_700_000_000i64;

        // 送信者 B の正常メッセージを先に登録
        assert!(
            cache
                .check_and_record("sender-b", "b-important", now, now)
                .is_ok()
        );

        // 送信者 A が 1,000件連投しても A は 500件上限に収まり、B は押し出されない
        for i in 0..1000 {
            cache
                .check_and_record("sender-a", &format!("a-{i}"), now, now + 1)
                .unwrap();
        }

        assert_eq!(cache.sender_len("sender-a"), 500);
        assert_eq!(cache.sender_len("sender-b"), 1);
        assert_eq!(cache.len(), 501);
        // 送信者 B のエントリはキャッシュに残っているためリプレイ検知が機能する
        assert_eq!(
            cache.check_and_record("sender-b", "b-important", now, now + 2),
            Err(ReplayCheckError::DuplicateMessage)
        );
    }

    #[test]
    fn ttl_expiration_and_global_limit_work() {
        let mut cache = ReplayCache::with_limits(300, 600, 5, 3);
        let t0 = 1_700_000_000i64;

        for i in 0..5 {
            cache
                .check_and_record(&format!("s-{i}"), "m1", t0, t0 + i as i64)
                .unwrap();
        }
        assert_eq!(cache.len(), 5);

        // 全体上限 5 超過で最古の s-0 が押し出される
        cache.check_and_record("s-5", "m1", t0, t0 + 10).unwrap();
        assert_eq!(cache.len(), 5);
        assert_eq!(cache.sender_len("s-0"), 0);

        // 600秒超過後の purge で全失効
        let purged = cache.purge_expired(t0 + 615);
        assert_eq!(purged, 5);
        assert_eq!(cache.len(), 0);
    }
}
