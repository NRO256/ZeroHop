use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX_TRACKED_IPS: usize = 512;

#[derive(Debug)]
pub struct UdpIpRateLimiter {
    max_per_window: usize,
    window: Duration,
    entries: HashMap<IpAddr, VecDeque<Instant>>,
}

impl UdpIpRateLimiter {
    pub fn new(max_per_window: usize, window: Duration) -> Self {
        Self {
            max_per_window: max_per_window.max(1),
            window,
            entries: HashMap::new(),
        }
    }

    pub fn default_udp() -> Self {
        Self::new(10, Duration::from_secs(1))
    }

    pub fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        if self.entries.len() >= MAX_TRACKED_IPS && !self.entries.contains_key(&ip) {
            self.prune_stale(now);
            if self.entries.len() >= MAX_TRACKED_IPS {
                self.evict_oldest(now);
            }
        }

        let queue = self.entries.entry(ip).or_default();
        while let Some(&front) = queue.front() {
            if now.saturating_duration_since(front) >= self.window {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.max_per_window {
            return false;
        }
        queue.push_back(now);
        true
    }

    fn prune_stale(&mut self, now: Instant) {
        let window = self.window;
        self.entries.retain(|_, queue| {
            while let Some(&front) = queue.front() {
                if now.saturating_duration_since(front) >= window {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
    }

    fn evict_oldest(&mut self, now: Instant) {
        let oldest_ip = self
            .entries
            .iter()
            .min_by_key(|(_, queue)| queue.back().copied().unwrap_or(now))
            .map(|(ip, _)| *ip);
        if let Some(ip) = oldest_ip {
            self.entries.remove(&ip);
        }
    }
}

/// 二段階異常通知レート制限（送信元 IP 単位 60秒に1回 ＋ アプリ全体 60秒に最大 10通知）
#[derive(Debug)]
pub struct AnomalyRateLimiter {
    per_ip_window: Duration,
    global_window: Duration,
    global_max: usize,
    per_ip_last: HashMap<IpAddr, Instant>,
    global_history: VecDeque<Instant>,
}

impl AnomalyRateLimiter {
    pub fn new(per_ip_window: Duration, global_window: Duration, global_max: usize) -> Self {
        Self {
            per_ip_window,
            global_window,
            global_max: global_max.max(1),
            per_ip_last: HashMap::new(),
            global_history: VecDeque::new(),
        }
    }

    pub fn default_anomaly() -> Self {
        Self::new(Duration::from_secs(60), Duration::from_secs(60), 10)
    }

    pub fn allow_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        while let Some(&front) = self.global_history.front() {
            if now.saturating_duration_since(front) >= self.global_window {
                self.global_history.pop_front();
            } else {
                break;
            }
        }

        if self.global_history.len() >= self.global_max {
            return false;
        }

        if let Some(&last) = self.per_ip_last.get(&ip)
            && now.saturating_duration_since(last) < self.per_ip_window
        {
            return false;
        }

        if self.per_ip_last.len() >= MAX_TRACKED_IPS && !self.per_ip_last.contains_key(&ip) {
            let win = self.per_ip_window;
            self.per_ip_last
                .retain(|_, &mut ts| now.saturating_duration_since(ts) < win);
            if self.per_ip_last.len() >= MAX_TRACKED_IPS {
                return false;
            }
        }

        self.per_ip_last.insert(ip, now);
        self.global_history.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn udp_ip_limiter_caps_10_packets_per_second_per_ip() {
        let mut limiter = UdpIpRateLimiter::default_udp();
        let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 10));
        let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 11));
        let t0 = Instant::now();

        for _ in 0..10 {
            assert!(limiter.allow_at(ip_a, t0));
        }
        assert!(!limiter.allow_at(ip_a, t0));
        assert!(limiter.allow_at(ip_b, t0));
        assert!(limiter.allow_at(ip_a, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn anomaly_limiter_enforces_per_ip_and_global_caps() {
        let mut limiter = AnomalyRateLimiter::default_anomaly();
        let t0 = Instant::now();
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1));

        // 同一 IP は 60秒内に1回のみ許可
        assert!(limiter.allow_at(ip1, t0));
        assert!(!limiter.allow_at(ip1, t0 + Duration::from_secs(59)));

        // 別 IP 群も全体上限 10件で抑止される
        for i in 2..=10 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, i));
            assert!(limiter.allow_at(ip, t0 + Duration::from_secs(1)));
        }
        let ip11 = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 11));
        assert!(!limiter.allow_at(ip11, t0 + Duration::from_secs(2)));

        // 60秒経過で再度許可
        assert!(limiter.allow_at(ip1, t0 + Duration::from_secs(60)));
        assert!(limiter.allow_at(ip11, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn udp_ip_limiter_evicts_oldest_ip_instead_of_starving_new_peers() {
        let mut limiter = UdpIpRateLimiter::default_udp();
        let t0 = Instant::now();

        for i in 0..MAX_TRACKED_IPS {
            let b2 = ((i >> 8) & 0xFF) as u8;
            let b3 = (i & 0xFF) as u8;
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, b2, b3));
            assert!(limiter.allow_at(ip, t0 + Duration::from_millis(i as u64)));
        }

        // 513 番目の正規 IP は最古 (10.0.0.0) を LRU 退避して受理される
        let legitimate_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 50));
        assert!(limiter.allow_at(legitimate_ip, t0 + Duration::from_millis(600)));
        assert_eq!(limiter.entries.len(), MAX_TRACKED_IPS);
    }
}
