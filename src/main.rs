#![windows_subsystem = "windows"]

mod ui;

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_LISTVIEW_CLASSES, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx,
};

use zerohop::crypto;
use zerohop::storage::{
    cache_wipe,
    config::{self, ConfigLoadResult},
    paths::AppPaths,
};

const SINGLE_INSTANCE_MUTEX: &str = "Local\\NRO_Antigravity_ZeroHop_SingleInstance";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliFlags {
    multi_instance: bool,
}

fn parse_cli_flags<I, S>(args: I) -> CliFlags
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut multi_instance = false;
    for arg in args.into_iter().skip(1) {
        if arg.as_ref().eq_ignore_ascii_case("--multi") {
            multi_instance = true;
        }
    }
    CliFlags { multi_instance }
}

struct SingleInstanceGuard(HANDLE);

impl SingleInstanceGuard {
    fn acquire() -> Option<Self> {
        let name_w = ui::to_wide(SINGLE_INSTANCE_MUTEX);
        unsafe {
            let handle = CreateMutexW(null_mut(), 0, name_w.as_ptr());
            if handle.is_null() {
                return None;
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(handle);
                return None;
            }
            Some(Self(handle))
        }
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = null_mut();
        }
    }
}

fn main() {
    crypto::disable_crash_dialogs();

    let flags = parse_cli_flags(std::env::args());
    let _instance_guard = if flags.multi_instance {
        None
    } else {
        let Some(guard) = SingleInstanceGuard::acquire() else {
            ui::dialogs::show_single_instance_warning();
            return;
        };
        Some(guard)
    };

    let Ok(app_paths) = AppPaths::from_current_exe() else {
        return;
    };

    crypto::kdf::install_emergency_panic_hook(app_paths.cache_dir());
    let _ = cache_wipe::wipe_cache_dir(&app_paths);

    let (initial_config, startup_notice) = match config::load_config(&app_paths) {
        ConfigLoadResult::Loaded(cfg) | ConfigLoadResult::NotFoundUsingDefault(cfg) => (cfg, None),
        ConfigLoadResult::CorruptedUsingDefault { config, .. } => (
            config,
            Some("config.json が破損していたため既定設定で起動しました。".to_string()),
        ),
    };

    let icc: INITCOMMONCONTROLSEX = unsafe {
        let mut s: INITCOMMONCONTROLSEX = zeroed();
        s.dwSize = size_of::<INITCOMMONCONTROLSEX>() as u32;
        s.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_BAR_CLASSES;
        s
    };
    unsafe {
        InitCommonControlsEx(&raw const icc);
    }

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        return;
    };

    let _exit_code = ui::run_app(
        app_paths,
        initial_config,
        flags.multi_instance,
        startup_notice,
        &runtime,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_flags_detects_multi_case_insensitively() {
        assert_eq!(
            parse_cli_flags(["ZeroHop.exe"]),
            CliFlags {
                multi_instance: false
            }
        );
        assert_eq!(
            parse_cli_flags(["ZeroHop.exe", "--multi"]),
            CliFlags {
                multi_instance: true
            }
        );
        assert_eq!(
            parse_cli_flags(["ZeroHop.exe", "--MULTI"]),
            CliFlags {
                multi_instance: true
            }
        );
    }
}
