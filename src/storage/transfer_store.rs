use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::crypto::aead::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, decrypt_aead, encrypt_aead, generate_nonce,
};
use crate::domain::model::MAX_FILE_TRANSFER_BYTES;
use crate::domain::protocol::MAX_FILE_CHUNK_RAW_BYTES;
use crate::domain::validation::validate_identifier;
use crate::storage::cache_wipe::{clear_readonly_if_needed, overwrite_zero_best_effort};
use crate::storage::paths::AppPaths;

const IO_BUF_BYTES: usize = MAX_FILE_CHUNK_RAW_BYTES;

#[derive(Debug, Error)]
pub enum TransferStoreError {
    #[error("I/Oエラー: {0}")]
    Io(#[from] std::io::Error),
    #[error("不正な転送IDです")]
    InvalidTransferId,
    #[error("ファイルサイズは1バイト以上50 MiB以下である必要があります")]
    InvalidFileSize,
    #[error("チャンク順序またはサイズが不正です")]
    InvalidChunk,
    #[error("一時ファイルの暗号化または復号に失敗しました")]
    CryptoFailed,
    #[error("受信ファイルのサイズまたはSHA-256チェックサムが一致しません")]
    ChecksumMismatch,
}

fn chunk_aad(transfer_id: &str, chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(transfer_id.len() + 8);
    aad.extend_from_slice(transfer_id.as_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad
}

fn format_sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

/// 送信対象ファイルのサイズ検証とストリーミング SHA-256 計算を行う（全量メモリ読込なし）。
pub fn compute_file_sha256_streaming(path: &Path) -> Result<(u64, String), TransferStoreError> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(TransferStoreError::InvalidFileSize);
    }
    let file_len = meta.len();
    if file_len == 0 || file_len > MAX_FILE_TRANSFER_BYTES {
        return Err(TransferStoreError::InvalidFileSize);
    }

    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(IO_BUF_BYTES, file);
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; IO_BUF_BYTES]);
    let mut total_read: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total_read = total_read
            .checked_add(n as u64)
            .ok_or(TransferStoreError::InvalidFileSize)?;
        if total_read > MAX_FILE_TRANSFER_BYTES {
            return Err(TransferStoreError::InvalidFileSize);
        }
        hasher.update(&buf[..n]);
    }

    if total_read == 0 {
        return Err(TransferStoreError::InvalidFileSize);
    }

    let digest = hasher.finalize();
    Ok((total_read, format_sha256_hex(&digest)))
}

/// Phase 3 受信中一時ファイルをセッション揮発鍵 `temp_disk_key` で暗号化保持し、
/// 完了・中断・Drop のいずれの経路でもゼロ上書き削除するガード構造体。
pub struct EncryptedTransferTempFile {
    path: PathBuf,
    transfers_dir: PathBuf,
    cache_dir: PathBuf,
    transfer_id: String,
    file: Option<File>,
    next_chunk_index: u64,
    total_plain_bytes: u64,
    cleaned_up: bool,
}

impl EncryptedTransferTempFile {
    pub fn create(paths: &AppPaths, transfer_id: &str) -> Result<Self, TransferStoreError> {
        validate_identifier(transfer_id).map_err(|_| TransferStoreError::InvalidTransferId)?;
        let cache_dir = paths.cache_dir();
        let transfers_dir = paths.transfers_dir();
        std::fs::create_dir_all(&transfers_dir)?;

        let path = transfers_dir.join(format!("{transfer_id}.enc"));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;

        Ok(Self {
            path,
            transfers_dir,
            cache_dir,
            transfer_id: transfer_id.to_string(),
            file: Some(file),
            next_chunk_index: 0,
            total_plain_bytes: 0,
            cleaned_up: false,
        })
    }

    pub fn total_plain_bytes(&self) -> u64 {
        self.total_plain_bytes
    }

    pub fn temp_path(&self) -> &Path {
        &self.path
    }

    pub fn append_encrypted_chunk(
        &mut self,
        temp_disk_key: &[u8; 32],
        chunk_index: u64,
        plain_chunk: &[u8],
    ) -> Result<(), TransferStoreError> {
        if chunk_index != self.next_chunk_index
            || plain_chunk.is_empty()
            || plain_chunk.len() > MAX_FILE_CHUNK_RAW_BYTES
        {
            return Err(TransferStoreError::InvalidChunk);
        }
        let next_total = self
            .total_plain_bytes
            .checked_add(plain_chunk.len() as u64)
            .ok_or(TransferStoreError::InvalidFileSize)?;
        if next_total > MAX_FILE_TRANSFER_BYTES {
            return Err(TransferStoreError::InvalidFileSize);
        }

        let nonce = generate_nonce();
        let aad = chunk_aad(&self.transfer_id, chunk_index);
        let ciphertext = encrypt_aead(temp_disk_key, &nonce, &aad, plain_chunk)
            .map_err(|_| TransferStoreError::CryptoFailed)?;
        let ct_len =
            u32::try_from(ciphertext.len()).map_err(|_| TransferStoreError::InvalidChunk)?;

        let file = self.file.as_mut().ok_or_else(|| {
            TransferStoreError::Io(std::io::Error::other("一時ファイルが閉じられています"))
        })?;

        file.write_all(&ct_len.to_be_bytes())?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;

        self.next_chunk_index += 1;
        self.total_plain_bytes = next_total;
        Ok(())
    }

    /// 受信完了後、一時ファイルを復号しながら全体 SHA-256 を検証し、一致時のみ `dest_path` を確定する。
    /// 完了・失敗いずれの場合も一時ファイルはシュレッディング削除される。
    pub fn finalize_and_verify(
        mut self,
        temp_disk_key: &[u8; 32],
        dest_path: &Path,
        expected_size: u64,
        expected_sha256_hex: &str,
    ) -> Result<(), TransferStoreError> {
        let result =
            self.finalize_inner(temp_disk_key, dest_path, expected_size, expected_sha256_hex);
        self.shred_and_cleanup();
        result
    }

    fn finalize_inner(
        &mut self,
        temp_disk_key: &[u8; 32],
        dest_path: &Path,
        expected_size: u64,
        expected_sha256_hex: &str,
    ) -> Result<(), TransferStoreError> {
        if self.total_plain_bytes != expected_size {
            return Err(TransferStoreError::ChecksumMismatch);
        }

        let mut file = self.file.take().ok_or_else(|| {
            TransferStoreError::Io(std::io::Error::other("一時ファイルが不在です"))
        })?;
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;

        let out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dest_path)?;
        let mut writer = BufWriter::with_capacity(IO_BUF_BYTES, out_file);
        let mut hasher = Sha256::new();
        let mut written_bytes: u64 = 0;

        let max_ct_len = MAX_FILE_CHUNK_RAW_BYTES + AEAD_TAG_LEN;
        let decrypt_res = (|| -> Result<(), TransferStoreError> {
            for chunk_idx in 0..self.next_chunk_index {
                let mut len_buf = [0u8; 4];
                file.read_exact(&mut len_buf)?;
                let ct_len = u32::from_be_bytes(len_buf) as usize;
                if ct_len < AEAD_TAG_LEN || ct_len > max_ct_len {
                    return Err(TransferStoreError::CryptoFailed);
                }

                let mut nonce = [0u8; AEAD_NONCE_LEN];
                file.read_exact(&mut nonce)?;

                let mut ciphertext = vec![0u8; ct_len];
                file.read_exact(&mut ciphertext)?;

                let aad = chunk_aad(&self.transfer_id, chunk_idx);
                let plain = decrypt_aead(temp_disk_key, &nonce, &aad, &ciphertext)
                    .map_err(|_| TransferStoreError::CryptoFailed)?;
                hasher.update(&plain);
                writer.write_all(&plain)?;
                written_bytes += plain.len() as u64;
            }
            writer.flush()?;
            Ok(())
        })();

        drop(writer);
        // 再利用中の file を戻して Drop/cleanup で確実に閉じる
        self.file = Some(file);

        if let Err(err) = decrypt_res {
            let _ = std::fs::remove_file(dest_path);
            return Err(err);
        }

        if written_bytes != expected_size {
            let _ = std::fs::remove_file(dest_path);
            return Err(TransferStoreError::ChecksumMismatch);
        }

        let actual_hex = format_sha256_hex(&hasher.finalize());
        let expected_lower = expected_sha256_hex.to_ascii_lowercase();
        let matched = actual_hex.len() == expected_lower.len()
            && bool::from(actual_hex.as_bytes().ct_eq(expected_lower.as_bytes()));
        if !matched {
            let _ = std::fs::remove_file(dest_path);
            return Err(TransferStoreError::ChecksumMismatch);
        }

        Ok(())
    }

    pub fn shred_and_cleanup(&mut self) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;
        if let Some(mut f) = self.file.take() {
            let _ = f.flush();
            drop(f);
        }
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            clear_readonly_if_needed(&self.path, false);
            overwrite_zero_best_effort(&self.path, meta.len());
            let _ = std::fs::remove_file(&self.path);
        }
        // 他の転送が進行中でなければ空フォルダを掃除
        let _ = std::fs::remove_dir(&self.transfers_dir);
        let _ = std::fs::remove_dir(&self.cache_dir);
    }
}

impl Drop for EncryptedTransferTempFile {
    fn drop(&mut self) {
        self.shred_and_cleanup();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lmsg_transfer_store_{name}_{}_{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn encrypted_temp_file_hides_plaintext_verifies_sha256_and_shreds_on_complete() {
        let base = temp_dir("ok");
        let paths = AppPaths::from_base_dir(base.clone());
        let src = base.join("source.bin");
        let dest = base.join("received.bin");
        let payload =
            b"Sensitive secret payload that must NEVER appear in plaintext inside cache/transfers!";
        std::fs::write(&src, payload).unwrap();

        let (size, sha_hex) = compute_file_sha256_streaming(&src).unwrap();
        assert_eq!(size, payload.len() as u64);

        let key = [0xA5u8; 32];
        let mut temp = EncryptedTransferTempFile::create(&paths, "tr-1").unwrap();
        temp.append_encrypted_chunk(&key, 0, &payload[..32])
            .unwrap();
        temp.append_encrypted_chunk(&key, 1, &payload[32..])
            .unwrap();

        // 一時ファイルに平文が含まれないことを検証
        let enc_bytes = std::fs::read(temp.temp_path()).unwrap();
        assert!(
            !enc_bytes.windows(6).any(|w| w == b"secret"),
            "暗号化一時ファイルに平文が露出しています"
        );

        temp.finalize_and_verify(&key, &dest, size, &sha_hex)
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        assert!(
            !paths.cache_dir().exists(),
            "完了後に空の cache/ が残っています"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn checksum_mismatch_deletes_dest_and_shreds_temp() {
        let base = temp_dir("bad_sha");
        let paths = AppPaths::from_base_dir(base.clone());
        let dest = base.join("should_not_exist.bin");
        let key = [0x11u8; 32];
        let mut temp = EncryptedTransferTempFile::create(&paths, "tr-bad").unwrap();
        temp.append_encrypted_chunk(&key, 0, b"hello world")
            .unwrap();

        let bad_sha = "0".repeat(64);
        let err = temp
            .finalize_and_verify(&key, &dest, 11, &bad_sha)
            .unwrap_err();
        assert!(matches!(err, TransferStoreError::ChecksumMismatch));
        assert!(
            !dest.exists(),
            "SHA-256不一致時に不完全な出力ファイルが残っています"
        );
        assert!(!paths.cache_dir().exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn drop_without_finalize_shreds_temp_file() {
        let base = temp_dir("drop");
        let paths = AppPaths::from_base_dir(base.clone());
        let key = [0x22u8; 32];
        let enc_path = {
            let mut temp = EncryptedTransferTempFile::create(&paths, "tr-drop").unwrap();
            temp.append_encrypted_chunk(&key, 0, b"aborted chunk")
                .unwrap();
            let p = temp.temp_path().to_path_buf();
            assert!(p.exists());
            p
        };
        assert!(
            !enc_path.exists(),
            "Drop 時に一時ファイルが削除されていません"
        );
        assert!(!paths.cache_dir().exists());

        let _ = std::fs::remove_dir_all(&base);
    }
}
