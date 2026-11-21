pub mod aead;
pub mod kdf;
pub mod replay;

use thiserror::Error;

use crate::domain::validation::ValidationError;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error(transparent)]
    InvalidPassword(#[from] ValidationError),
    #[error("鍵導出に失敗しました: {0}")]
    KdfFailed(String),
    #[error("AEAD暗号化に失敗しました")]
    EncryptionFailed,
    #[error("AEAD復号または認証検証に失敗しました")]
    DecryptionFailed,
    #[error("鍵はすでに消去されています")]
    KeyZeroized,
}

/// Windows のクラッシュダイアログおよび不要なエラーレポート表示を抑止する
#[cfg(windows)]
pub fn disable_crash_dialogs() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    unsafe {
        let _ = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}

#[cfg(not(windows))]
pub fn disable_crash_dialogs() {}
