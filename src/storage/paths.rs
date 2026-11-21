use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::StorageError;

static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    base_dir: PathBuf,
}

impl AppPaths {
    pub fn from_current_exe() -> Result<Self, StorageError> {
        let exe_path = std::env::current_exe()
            .map_err(|e| StorageError::PathNotResolved(format!("current_exe 取得失敗: {e}")))?;
        let base_dir = exe_path.parent().map(Path::to_path_buf).ok_or_else(|| {
            StorageError::PathNotResolved("親ディレクトリが存在しません".to_string())
        })?;
        Ok(Self { base_dir })
    }

    pub fn from_base_dir(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn config_path(&self) -> PathBuf {
        self.base_dir.join("config.json")
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.base_dir.join("cache")
    }

    pub fn transfers_dir(&self) -> PathBuf {
        self.cache_dir().join("transfers")
    }

    /// 書き込み権限の有無をプローブファイル作成→即削除で検査する（起動時に無条件で呼ばない）
    pub fn is_base_dir_writable(&self) -> bool {
        if !self.base_dir.is_dir() {
            return false;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
        let probe_name = format!(".lmsg_write_probe_{}_{}_{}", std::process::id(), nanos, seq);
        let probe_path = self.base_dir.join(probe_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe_path)
        {
            Ok(file) => {
                drop(file);
                let _ = std::fs::remove_file(&probe_path);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lmsg_paths_test_{name}_{}_{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn resolves_portable_paths_under_base_dir() {
        let base = PathBuf::from(r"C:\Portable\LMSG");
        let paths = AppPaths::from_base_dir(base.clone());
        assert_eq!(paths.base_dir(), base.as_path());
        assert_eq!(paths.config_path(), base.join("config.json"));
        assert_eq!(paths.cache_dir(), base.join("cache"));
        assert_eq!(paths.transfers_dir(), base.join("cache").join("transfers"));
    }

    #[test]
    fn detects_writable_and_nonexistent_base_dir() {
        let writable_dir = temp_dir("writable");
        let paths = AppPaths::from_base_dir(writable_dir.clone());
        assert!(paths.is_base_dir_writable());
        // プローブファイルが残存しないこと
        assert_eq!(std::fs::read_dir(&writable_dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&writable_dir);

        let missing = writable_dir.join("does_not_exist");
        let missing_paths = AppPaths::from_base_dir(missing);
        assert!(!missing_paths.is_base_dir_writable());
    }
}
