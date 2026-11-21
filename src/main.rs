#![windows_subsystem = "windows"]

use lan_messenger::crypto;
use lan_messenger::storage::{cache_wipe, config, paths::AppPaths};

fn main() {
    crypto::disable_crash_dialogs();

    let Ok(app_paths) = AppPaths::from_current_exe() else {
        return;
    };

    crypto::kdf::install_emergency_panic_hook(app_paths.cache_dir());
    let _ = cache_wipe::wipe_cache_dir(&app_paths);
    let _loaded = config::load_config(&app_paths);
    // Step 1-6 で Win32 GUI イベントループへ接続する
}
