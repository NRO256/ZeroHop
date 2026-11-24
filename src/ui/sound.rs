//! インメモリ PCM 動的合成効果音と PlaySoundW 再生調停（Phase 2 Step 2-1）。

use std::ptr::null_mut;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::Win32::Media::Audio::{
    PlaySoundW, SND_ASYNC, SND_MEMORY, SND_NODEFAULT, SND_SYNC,
};

use zerohop::storage::config::LocalConfig;

const SAMPLE_RATE: u32 = 22_050;
const CHANNELS: u16 = 1;
const BITS_PER_SAMPLE: u16 = 16;
const MAX_AMPLITUDE_RATIO: f64 = 0.18; // 18%（上限 20% 以下）
const FADE_MS: u32 = 12;
const WARMUP_SECS: u64 = 6;
const CONTENTION_WINDOW_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum SoundEvent {
    Login = 0,
    PeerJoined = 1,
    PeerLeft = 2,
    Logout = 3,
    MessageReceived = 4,
}

impl SoundEvent {
    pub const fn priority(self) -> u8 {
        match self {
            Self::PeerJoined | Self::PeerLeft => 1,
            Self::MessageReceived => 2,
            Self::Login | Self::Logout => 3,
        }
    }

    pub const fn cooldown(self) -> Duration {
        match self {
            Self::PeerJoined | Self::PeerLeft => Duration::from_millis(2000),
            Self::MessageReceived => Duration::from_millis(1500),
            Self::Login | Self::Logout => Duration::ZERO,
        }
    }

    pub const fn is_enabled_in(self, cfg: &LocalConfig) -> bool {
        if !cfg.sound_enabled {
            return false;
        }
        match self {
            Self::Login | Self::Logout => cfg.sound_on_login_logout,
            Self::PeerJoined | Self::PeerLeft => cfg.sound_on_peer_presence,
            Self::MessageReceived => cfg.sound_on_message,
        }
    }
}

pub(crate) struct SoundController {
    login_at: Option<Instant>,
    last_played_at: Option<Instant>,
    last_event_at: [Option<Instant>; 5],
}

impl Default for SoundController {
    fn default() -> Self {
        Self::new()
    }
}

impl SoundController {
    pub fn new() -> Self {
        Self {
            login_at: None,
            last_played_at: None,
            last_event_at: [None; 5],
        }
    }

    pub fn mark_login_at(&mut self, now: Instant) {
        self.login_at = Some(now);
        self.last_event_at = [None; 5];
    }

    pub fn mark_logout(&mut self) {
        self.login_at = None;
        self.last_played_at = None;
        self.last_event_at = [None; 5];
    }

    pub fn should_play(
        &mut self,
        event: SoundEvent,
        cfg: &LocalConfig,
        is_locked: bool,
        now: Instant,
    ) -> bool {
        if is_locked || !event.is_enabled_in(cfg) {
            return false;
        }

        if matches!(event, SoundEvent::PeerJoined | SoundEvent::PeerLeft)
            && let Some(login) = self.login_at
            && now.saturating_duration_since(login) < Duration::from_secs(WARMUP_SECS)
        {
            return false;
        }

        let cooldown = event.cooldown();
        if !cooldown.is_zero()
            && let Some(prev) = self.last_event_at[event as usize]
            && now.saturating_duration_since(prev) < cooldown
        {
            return false;
        }

        if let Some(prev_any) = self.last_played_at
            && now.saturating_duration_since(prev_any) < Duration::from_millis(CONTENTION_WINDOW_MS)
            && event.priority() < SoundEvent::Login.priority()
        {
            return false;
        }

        self.last_played_at = Some(now);
        self.last_event_at[event as usize] = Some(now);
        true
    }
}

fn wav_bytes_for(event: SoundEvent) -> &'static [u8] {
    static WAV_LOGIN: OnceLock<Vec<u8>> = OnceLock::new();
    static WAV_PEER_JOINED: OnceLock<Vec<u8>> = OnceLock::new();
    static WAV_PEER_LEFT: OnceLock<Vec<u8>> = OnceLock::new();
    static WAV_LOGOUT: OnceLock<Vec<u8>> = OnceLock::new();
    static WAV_MSG: OnceLock<Vec<u8>> = OnceLock::new();

    match event {
        SoundEvent::Login => WAV_LOGIN.get_or_init(|| synthesize_two_tone_wav(523.25, 659.25, 220)),
        SoundEvent::PeerJoined => WAV_PEER_JOINED.get_or_init(|| synthesize_tone_wav(783.99, 130)),
        SoundEvent::PeerLeft => WAV_PEER_LEFT.get_or_init(|| synthesize_tone_wav(440.0, 140)),
        SoundEvent::Logout => {
            WAV_LOGOUT.get_or_init(|| synthesize_two_tone_wav(659.25, 523.25, 240))
        }
        SoundEvent::MessageReceived => WAV_MSG.get_or_init(|| synthesize_tone_wav(880.0, 120)),
    }
}

fn synthesize_tone_wav(freq_hz: f64, duration_ms: u32) -> Vec<u8> {
    let total_samples = ((SAMPLE_RATE as u64 * u64::from(duration_ms)) / 1000) as usize;
    let fade_samples = ((SAMPLE_RATE as u64 * u64::from(FADE_MS)) / 1000) as usize;
    let mut samples = Vec::with_capacity(total_samples);
    let max_amp = f64::from(i16::MAX) * MAX_AMPLITUDE_RATIO;

    for i in 0..total_samples {
        let t = i as f64 / f64::from(SAMPLE_RATE);
        let env = envelope_gain(i, total_samples, fade_samples);
        let val = (2.0 * std::f64::consts::PI * freq_hz * t).sin() * max_amp * env;
        samples.push(val.round().clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16);
    }
    encode_pcm16_wav(&samples)
}

fn synthesize_two_tone_wav(freq1_hz: f64, freq2_hz: f64, duration_ms: u32) -> Vec<u8> {
    let total_samples = ((SAMPLE_RATE as u64 * u64::from(duration_ms)) / 1000) as usize;
    let half = total_samples / 2;
    let fade_samples = ((SAMPLE_RATE as u64 * u64::from(FADE_MS)) / 1000) as usize;
    let mut samples = Vec::with_capacity(total_samples);
    let max_amp = f64::from(i16::MAX) * MAX_AMPLITUDE_RATIO;
    let mut phase = 0.0_f64;

    for i in 0..total_samples {
        let freq = if i < half { freq1_hz } else { freq2_hz };
        phase += 2.0 * std::f64::consts::PI * freq / f64::from(SAMPLE_RATE);
        let env = envelope_gain(i, total_samples, fade_samples);
        let val = phase.sin() * max_amp * env;
        samples.push(val.round().clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16);
    }
    encode_pcm16_wav(&samples)
}

fn envelope_gain(index: usize, total: usize, fade_samples: usize) -> f64 {
    if total == 0 || fade_samples == 0 {
        return 1.0;
    }
    let fade = fade_samples.min(total / 2);
    if fade == 0 {
        return 1.0;
    }
    if index < fade {
        index as f64 / fade as f64
    } else if index >= total - fade {
        (total - 1 - index) as f64 / fade as f64
    } else {
        1.0
    }
}

fn encode_pcm16_wav(samples: &[i16]) -> Vec<u8> {
    let data_bytes = (samples.len() * 2) as u32;
    let byte_rate = SAMPLE_RATE * u32::from(CHANNELS) * u32::from(BITS_PER_SAMPLE / 8);
    let block_align = CHANNELS * (BITS_PER_SAMPLE / 8);
    let riff_size = 36_u32.saturating_add(data_bytes);

    let mut buf = Vec::with_capacity(44 + data_bytes as usize);
    buf.extend_from_slice(b"RIFF");
    buf.extend_from_slice(&riff_size.to_le_bytes());
    buf.extend_from_slice(b"WAVE");
    buf.extend_from_slice(b"fmt ");
    buf.extend_from_slice(&16_u32.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes()); // PCM
    buf.extend_from_slice(&CHANNELS.to_le_bytes());
    buf.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
    buf.extend_from_slice(&byte_rate.to_le_bytes());
    buf.extend_from_slice(&block_align.to_le_bytes());
    buf.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    buf.extend_from_slice(b"data");
    buf.extend_from_slice(&data_bytes.to_le_bytes());
    for &s in samples {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    buf
}

pub(crate) fn play_sound_if_allowed(
    controller: &mut SoundController,
    event: SoundEvent,
    cfg: &LocalConfig,
    is_locked: bool,
) {
    if !controller.should_play(event, cfg, is_locked, Instant::now()) {
        return;
    }
    let wav = wav_bytes_for(event);
    unsafe {
        PlaySoundW(
            wav.as_ptr() as *const u16,
            null_mut(),
            SND_MEMORY | SND_ASYNC | SND_NODEFAULT,
        );
    }
}

pub(crate) fn play_logout_on_exit_sync(cfg: &LocalConfig, is_locked: bool) {
    if is_locked || !SoundEvent::Logout.is_enabled_in(cfg) {
        return;
    }
    let wav = wav_bytes_for(SoundEvent::Logout);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        unsafe {
            PlaySoundW(
                wav.as_ptr() as *const u16,
                null_mut(),
                SND_MEMORY | SND_SYNC | SND_NODEFAULT,
            );
        }
        let _ = tx.send(());
    });
    let _ = rx.recv_timeout(Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peaks(wav: &[u8]) -> (u32, i16) {
        let data_size = u32::from_le_bytes(wav[40..44].try_into().unwrap());
        let mut peak = 0_i16;
        for &chunk in wav[44..].as_chunks::<2>().0 {
            let s = i16::from_le_bytes([chunk[0], chunk[1]]);
            peak = peak.max(s.saturating_abs());
        }
        (data_size, peak)
    }

    #[test]
    fn all_five_wav_buffers_have_valid_riff_headers_durations_and_amplitude_under_20_percent() {
        let max_allowed = ((f64::from(i16::MAX) * 0.20).ceil()) as i16;
        let expected = [
            (SoundEvent::Login, 220_u32),
            (SoundEvent::PeerJoined, 130_u32),
            (SoundEvent::PeerLeft, 140_u32),
            (SoundEvent::Logout, 240_u32),
            (SoundEvent::MessageReceived, 120_u32),
        ];

        for (ev, ms) in expected {
            let wav = wav_bytes_for(ev);
            assert_eq!(&wav[0..4], b"RIFF");
            assert_eq!(&wav[8..12], b"WAVE");
            assert_eq!(&wav[12..16], b"fmt ");
            assert_eq!(&wav[36..40], b"data");
            let sample_rate = u32::from_le_bytes(wav[24..28].try_into().unwrap());
            assert_eq!(sample_rate, SAMPLE_RATE);

            let (data_size, peak) = sample_peaks(wav);
            let expected_samples = ((u64::from(SAMPLE_RATE) * u64::from(ms)) / 1000) as u32;
            assert_eq!(data_size, expected_samples * 2);
            assert!(
                peak > 0 && peak <= max_allowed,
                "peak={peak} max={max_allowed}"
            );
        }
    }

    #[test]
    fn controller_enforces_warmup_cooldown_contention_mute_and_lock() {
        let mut ctrl = SoundController::new();
        let cfg = LocalConfig::default();
        let t0 = Instant::now();
        ctrl.mark_login_at(t0);

        // ログイン音はウォームアップ中でも鳴る
        assert!(ctrl.should_play(SoundEvent::Login, &cfg, false, t0));
        // 6秒ウォームアップ中はピア入退出を抑止
        assert!(!ctrl.should_play(
            SoundEvent::PeerJoined,
            &cfg,
            false,
            t0 + Duration::from_secs(3)
        ));
        // 新着メッセージはログイン直後 250ms 未満は競合抑止、250ms 以降は鳴る
        assert!(!ctrl.should_play(
            SoundEvent::MessageReceived,
            &cfg,
            false,
            t0 + Duration::from_millis(100)
        ));
        assert!(ctrl.should_play(
            SoundEvent::MessageReceived,
            &cfg,
            false,
            t0 + Duration::from_millis(300)
        ));
        // メッセージクールダウン 1.5秒
        assert!(!ctrl.should_play(
            SoundEvent::MessageReceived,
            &cfg,
            false,
            t0 + Duration::from_millis(1000)
        ));
        assert!(ctrl.should_play(
            SoundEvent::MessageReceived,
            &cfg,
            false,
            t0 + Duration::from_millis(1900)
        ));

        // 6秒経過後はピア入室が鳴り、2秒クールダウンが効く
        let t_warm = t0 + Duration::from_secs(7);
        assert!(ctrl.should_play(SoundEvent::PeerJoined, &cfg, false, t_warm));
        assert!(!ctrl.should_play(
            SoundEvent::PeerJoined,
            &cfg,
            false,
            t_warm + Duration::from_millis(1000)
        ));
        assert!(ctrl.should_play(
            SoundEvent::PeerJoined,
            &cfg,
            false,
            t_warm + Duration::from_millis(2100)
        ));

        // 画面ロック中は全抑止
        assert!(!ctrl.should_play(
            SoundEvent::Login,
            &cfg,
            true,
            t_warm + Duration::from_secs(5)
        ));

        // ミュート設定時は全抑止
        let mut muted = cfg.clone();
        muted.sound_enabled = false;
        assert!(!ctrl.should_play(
            SoundEvent::MessageReceived,
            &muted,
            false,
            t_warm + Duration::from_secs(5)
        ));
    }
}
