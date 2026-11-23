pub mod cache_wipe;
pub mod config;
pub mod paths;
pub mod transfer_store;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/Oエラー: {0}")]
    Io(#[from] std::io::Error),
    #[error("設定JSONシリアライズエラー: {0}")]
    Json(#[from] serde_json::Error),
    #[error("実行ディレクトリを解決できませんでした: {0}")]
    PathNotResolved(String),
}
