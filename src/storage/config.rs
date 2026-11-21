use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::domain::model::{
    DEFAULT_TCP_PORT, DEFAULT_UDP_PORT, MAX_MAX_MEMORY_MB, MIN_MAX_MEMORY_MB,
};
use crate::storage::StorageError;
use crate::storage::paths::AppPaths;

static SAVE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
pub const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// ディスク設定ファイル（config.json — 非機密動作設定のみ）
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct LocalConfig {
    pub udp_port: u16,
    pub tcp_port: u16,
    pub preferred_nic_ip: Option<String>,
    pub max_memory_mb: u16,
    pub sound_enabled: bool,
    pub sound_on_login_logout: bool,
    pub sound_on_peer_presence: bool,
    pub sound_on_message: bool,
    pub send_on_enter: bool,
    pub hide_notification_preview: bool,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            udp_port: DEFAULT_UDP_PORT,
            tcp_port: DEFAULT_TCP_PORT,
            preferred_nic_ip: None,
            max_memory_mb: 16,
            sound_enabled: true,
            sound_on_login_logout: true,
            sound_on_peer_presence: true,
            sound_on_message: true,
            send_on_enter: false,
            hide_notification_preview: false,
        }
    }
}

impl LocalConfig {
    pub fn sanitize(&mut self) {
        if self.udp_port == 0 {
            self.udp_port = DEFAULT_UDP_PORT;
        }
        if self.tcp_port == 0 {
            self.tcp_port = DEFAULT_TCP_PORT;
        }
        self.max_memory_mb = self
            .max_memory_mb
            .clamp(MIN_MAX_MEMORY_MB, MAX_MAX_MEMORY_MB);

        self.preferred_nic_ip = self
            .preferred_nic_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.parse::<IpAddr>().is_ok())
            .map(ToString::to_string);
    }

    pub fn max_total_log_bytes(&self) -> usize {
        usize::from(
            self.max_memory_mb
                .clamp(MIN_MAX_MEMORY_MB, MAX_MAX_MEMORY_MB),
        ) * 1024
            * 1024
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLoadResult {
    Loaded(LocalConfig),
    NotFoundUsingDefault(LocalConfig),
    CorruptedUsingDefault { config: LocalConfig, reason: String },
}

impl ConfigLoadResult {
    pub fn config(&self) -> &LocalConfig {
        match self {
            Self::Loaded(cfg)
            | Self::NotFoundUsingDefault(cfg)
            | Self::CorruptedUsingDefault { config: cfg, .. } => cfg,
        }
    }

    pub fn into_config(self) -> LocalConfig {
        match self {
            Self::Loaded(cfg)
            | Self::NotFoundUsingDefault(cfg)
            | Self::CorruptedUsingDefault { config: cfg, .. } => cfg,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSaveOutcome {
    Saved,
    SkippedReadOnly { reason: String },
}

fn is_readonly_or_permission_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    )
}

pub fn load_config(paths: &AppPaths) -> ConfigLoadResult {
    let config_path = paths.config_path();
    let meta = match std::fs::metadata(&config_path) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return ConfigLoadResult::NotFoundUsingDefault(LocalConfig::default());
        }
        Err(err) => {
            return ConfigLoadResult::CorruptedUsingDefault {
                config: LocalConfig::default(),
                reason: format!("設定ファイルメタデータ読込エラー: {err}"),
            };
        }
    };
    if meta.len() > MAX_CONFIG_FILE_BYTES {
        return ConfigLoadResult::CorruptedUsingDefault {
            config: LocalConfig::default(),
            reason: format!(
                "設定ファイルサイズが上限（{MAX_CONFIG_FILE_BYTES} バイト）を超過しています: {} バイト",
                meta.len()
            ),
        };
    }
    let content = match std::fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return ConfigLoadResult::NotFoundUsingDefault(LocalConfig::default());
        }
        Err(err) => {
            return ConfigLoadResult::CorruptedUsingDefault {
                config: LocalConfig::default(),
                reason: format!("設定ファイル読込エラー: {err}"),
            };
        }
    };

    match serde_json::from_str::<LocalConfig>(&content) {
        Ok(mut cfg) => {
            cfg.sanitize();
            ConfigLoadResult::Loaded(cfg)
        }
        Err(err) => ConfigLoadResult::CorruptedUsingDefault {
            config: LocalConfig::default(),
            reason: format!("設定JSON解析失敗: {err}"),
        },
    }
}

pub fn save_config(
    paths: &AppPaths,
    config: &LocalConfig,
) -> Result<ConfigSaveOutcome, StorageError> {
    let mut sanitized = config.clone();
    sanitized.sanitize();
    let json = serde_json::to_string_pretty(&sanitized)?;

    let config_path = paths.config_path();
    if let Ok(meta) = std::fs::metadata(&config_path)
        && meta.permissions().readonly()
    {
        return Ok(ConfigSaveOutcome::SkippedReadOnly {
            reason: "config.json が読み取り専用のため保存をスキップしました".to_string(),
        });
    }

    let seq = SAVE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path =
        paths
            .base_dir()
            .join(format!(".config.json.tmp.{}.{}", std::process::id(), seq));

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
    {
        Ok(f) => f,
        Err(err) if is_readonly_or_permission_error(&err) => {
            return Ok(ConfigSaveOutcome::SkippedReadOnly {
                reason: format!("書き込み不可フォルダのため保存をスキップしました: {err}"),
            });
        }
        Err(err) => return Err(StorageError::Io(err)),
    };

    if let Err(err) = file.write_all(json.as_bytes()).and_then(|()| file.flush()) {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        if is_readonly_or_permission_error(&err) {
            return Ok(ConfigSaveOutcome::SkippedReadOnly {
                reason: format!("書き込み不可のため保存をスキップしました: {err}"),
            });
        }
        return Err(StorageError::Io(err));
    }
    drop(file);

    match std::fs::rename(&tmp_path, &config_path) {
        Ok(()) => Ok(ConfigSaveOutcome::Saved),
        Err(err) if is_readonly_or_permission_error(&err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Ok(ConfigSaveOutcome::SkippedReadOnly {
                reason: format!("読み取り専用のため保存をスキップしました: {err}"),
            })
        }
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(StorageError::Io(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static CONFIG_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_test_dir(name: &str) -> PathBuf {
        let seq = CONFIG_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lmsg_config_test_{name}_{}_{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_config_returns_default_without_creating_file() {
        let dir = temp_test_dir("missing");
        let paths = AppPaths::from_base_dir(dir.clone());
        let res = load_config(&paths);
        assert_eq!(
            res,
            ConfigLoadResult::NotFoundUsingDefault(LocalConfig::default())
        );
        assert!(!paths.config_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_and_out_of_range_config_uses_serde_default_and_sanitize() {
        let dir = temp_test_dir("partial");
        let paths = AppPaths::from_base_dir(dir.clone());
        std::fs::write(
            paths.config_path(),
            r#"{"udp_port": 0, "max_memory_mb": 999, "preferred_nic_ip": "not-an-ip"}"#,
        )
        .unwrap();

        let res = load_config(&paths);
        match res {
            ConfigLoadResult::Loaded(cfg) => {
                assert_eq!(cfg.udp_port, DEFAULT_UDP_PORT);
                assert_eq!(cfg.tcp_port, DEFAULT_TCP_PORT);
                assert_eq!(cfg.max_memory_mb, MAX_MAX_MEMORY_MB);
                assert_eq!(cfg.preferred_nic_ip, None);
                assert!(cfg.sound_enabled);
                assert!(!cfg.send_on_enter);
            }
            other => panic!("unexpected result: {other:?}"),
        }

        std::fs::write(paths.config_path(), "{ invalid json").unwrap();
        let corrupt = load_config(&paths);
        assert!(matches!(
            corrupt,
            ConfigLoadResult::CorruptedUsingDefault { .. }
        ));

        let oversized = " ".repeat((MAX_CONFIG_FILE_BYTES as usize) + 1);
        std::fs::write(paths.config_path(), oversized).unwrap();
        let oversized_res = load_config(&paths);
        assert!(matches!(
            oversized_res,
            ConfigLoadResult::CorruptedUsingDefault { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_config_writes_non_secret_fields_and_skips_readonly_file() {
        let dir = temp_test_dir("save_ro");
        let paths = AppPaths::from_base_dir(dir.clone());
        let cfg = LocalConfig {
            udp_port: 45200,
            tcp_port: 45201,
            preferred_nic_ip: Some("192.168.1.20".to_string()),
            max_memory_mb: 8,
            ..LocalConfig::default()
        };

        assert_eq!(save_config(&paths, &cfg).unwrap(), ConfigSaveOutcome::Saved);
        let raw = std::fs::read_to_string(paths.config_path()).unwrap();
        assert!(!raw.contains("display_name"));
        assert!(!raw.contains("password"));
        assert!(!raw.contains("peer_id"));
        assert!(!raw.contains("msg_key"));

        let loaded = load_config(&paths).into_config();
        assert_eq!(loaded, cfg);

        // 既存 config.json を読み取り専用に設定した場合は SkippedReadOnly で失敗しない
        let mut perms = std::fs::metadata(paths.config_path())
            .unwrap()
            .permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(paths.config_path(), perms).unwrap();

        let outcome = save_config(&paths, &LocalConfig::default()).unwrap();
        assert!(matches!(outcome, ConfigSaveOutcome::SkippedReadOnly { .. }));

        // 掃除前に読み取り専用属性を解除
        #[allow(clippy::permissions_set_readonly_false)]
        {
            let mut reset = std::fs::metadata(paths.config_path())
                .unwrap()
                .permissions();
            reset.set_readonly(false);
            std::fs::set_permissions(paths.config_path(), reset).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
