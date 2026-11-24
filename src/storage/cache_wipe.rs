use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;

use crate::storage::StorageError;
use crate::storage::paths::AppPaths;

const MAX_ZERO_WIPE_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_BUF_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheWipeReport {
    pub existed: bool,
    pub removed_files: usize,
    pub removed_dirs: usize,
}

#[allow(clippy::permissions_set_readonly_false)]
pub(crate) fn clear_readonly_if_needed(path: &Path, is_dir: bool) {
    if is_dir {
        return;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

pub(crate) fn overwrite_zero_best_effort(path: &Path, file_len: u64) {
    if file_len == 0 || file_len > MAX_ZERO_WIPE_BYTES {
        return;
    }
    let Ok(mut file) = OpenOptions::new().write(true).open(path) else {
        return;
    };
    let zeros = [0u8; ZERO_BUF_SIZE];
    let mut remaining = file_len;
    while remaining > 0 {
        let chunk_len = remaining.min(ZERO_BUF_SIZE as u64) as usize;
        if file.write_all(&zeros[..chunk_len]).is_err() {
            break;
        }
        remaining -= chunk_len as u64;
    }
    let _ = file.flush();
}

fn wipe_recursive(dir: &Path, report: &mut CacheWipeReport) -> Result<(), StorageError> {
    let entries = std::fs::read_dir(dir)?;
    for entry_res in entries {
        let entry = entry_res?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            if meta.is_dir() {
                std::fs::remove_dir(&path)?;
                report.removed_dirs += 1;
            } else {
                std::fs::remove_file(&path)?;
                report.removed_files += 1;
            }
        } else if file_type.is_dir() {
            wipe_recursive(&path, report)?;
        } else {
            clear_readonly_if_needed(&path, false);
            overwrite_zero_best_effort(&path, meta.len());
            std::fs::remove_file(&path)?;
            report.removed_files += 1;
        }
    }

    std::fs::remove_dir(dir)?;
    report.removed_dirs += 1;
    Ok(())
}

pub fn wipe_cache_dir_at(cache_dir: &Path) -> Result<CacheWipeReport, StorageError> {
    let meta = match std::fs::symlink_metadata(cache_dir) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(CacheWipeReport::default());
        }
        Err(err) => return Err(StorageError::Io(err)),
    };

    let mut report = CacheWipeReport {
        existed: true,
        removed_files: 0,
        removed_dirs: 0,
    };

    let file_type = meta.file_type();
    if file_type.is_symlink() {
        if meta.is_dir() {
            std::fs::remove_dir(cache_dir)?;
            report.removed_dirs += 1;
        } else {
            std::fs::remove_file(cache_dir)?;
            report.removed_files += 1;
        }
        return Ok(report);
    }

    if file_type.is_dir() {
        wipe_recursive(cache_dir, &mut report)?;
    } else {
        clear_readonly_if_needed(cache_dir, false);
        overwrite_zero_best_effort(cache_dir, meta.len());
        std::fs::remove_file(cache_dir)?;
        report.removed_files += 1;
    }

    Ok(report)
}

pub fn wipe_cache_dir(paths: &AppPaths) -> Result<CacheWipeReport, StorageError> {
    wipe_cache_dir_at(&paths.cache_dir())
}

pub fn wipe_cache_dir_best_effort(cache_dir: &Path) {
    let _ = wipe_cache_dir_at(cache_dir);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static WIPE_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_base(name: &str) -> PathBuf {
        let seq = WIPE_TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zhop_wipe_test_{name}_{}_{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_cache_dir_is_noop_and_creates_nothing() {
        let base = temp_base("noop");
        let paths = AppPaths::from_base_dir(base.clone());
        let report = wipe_cache_dir(&paths).unwrap();
        assert_eq!(report, CacheWipeReport::default());
        assert!(!paths.cache_dir().exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn wipes_nested_and_readonly_cache_files() {
        let base = temp_base("nested");
        let paths = AppPaths::from_base_dir(base.clone());
        let transfers = paths.transfers_dir();
        std::fs::create_dir_all(&transfers).unwrap();

        let f1 = transfers.join("part1.enc");
        std::fs::write(&f1, b"encrypted-temp-bytes").unwrap();
        let mut perms = std::fs::metadata(&f1).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&f1, perms).unwrap();

        let f2 = paths.cache_dir().join("leftover.tmp");
        std::fs::write(&f2, b"residual").unwrap();

        let report = wipe_cache_dir(&paths).unwrap();
        assert!(report.existed);
        assert_eq!(report.removed_files, 2);
        assert_eq!(report.removed_dirs, 2);
        assert!(!paths.cache_dir().exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
