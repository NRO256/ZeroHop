use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{HWND, S_OK, SysAllocString, SysFreeString};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

const NOTIFICATION_KIND_ACTION_COMPLETED: i32 = 4;
const NOTIFICATION_PROCESSING_MOST_RECENT: i32 = 3;
const MAX_ANNOUNCE_CHARS: usize = 300;

type UiaClientsAreListeningFn = unsafe extern "system" fn() -> i32;
type UiaHostProviderFromHwndFn =
    unsafe extern "system" fn(hwnd: HWND, pp_provider: *mut *mut c_void) -> i32;
type UiaRaiseNotificationEventFn = unsafe extern "system" fn(
    provider: *mut c_void,
    notification_kind: i32,
    notification_processing: i32,
    display_string: *const u16,
    activity_id: *const u16,
) -> i32;

struct UiaApi {
    clients_are_listening: UiaClientsAreListeningFn,
    host_provider_from_hwnd: UiaHostProviderFromHwndFn,
    raise_notification_event: UiaRaiseNotificationEventFn,
}

static UIA_API: OnceLock<Option<UiaApi>> = OnceLock::new();

fn load_uia_api() -> Option<&'static UiaApi> {
    UIA_API
        .get_or_init(|| {
            let dll_w: Vec<u16> = "UIAutomationCore.dll\0".encode_utf16().collect();
            // SAFETY: 固定の System32 DLL 名を LOAD_LIBRARY_SEARCH_SYSTEM32 で安全に読み込む。
            let hmod = unsafe {
                LoadLibraryExW(
                    dll_w.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if hmod.is_null() {
                return None;
            }
            // SAFETY: UIAutomationCore.dll から公開関数シンボルを取得する。
            unsafe {
                let p_listening = GetProcAddress(hmod, c"UiaClientsAreListening".as_ptr().cast())?;
                let p_host = GetProcAddress(hmod, c"UiaHostProviderFromHwnd".as_ptr().cast())?;
                let p_raise = GetProcAddress(hmod, c"UiaRaiseNotificationEvent".as_ptr().cast())?;
                Some(UiaApi {
                    clients_are_listening: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        UiaClientsAreListeningFn,
                    >(p_listening),
                    host_provider_from_hwnd: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        UiaHostProviderFromHwndFn,
                    >(p_host),
                    raise_notification_event: std::mem::transmute::<
                        unsafe extern "system" fn() -> isize,
                        UiaRaiseNotificationEventFn,
                    >(p_raise),
                })
            }
        })
        .as_ref()
}

struct ProviderGuard(*mut c_void);

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: IRawElementProviderSimple は IUnknown を継承しており、vtable[2] は Release。
            unsafe {
                let vtbl = *(self.0 as *const *const *const c_void);
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(*vtbl.add(2));
                release(self.0);
            }
        }
    }
}

struct Bstr(*const u16);

impl Bstr {
    fn new(text: &str) -> Option<Self> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: NULL 終端済み UTF-16 スライスから BSTR を割り当てる。
        let ptr = unsafe { SysAllocString(wide.as_ptr()) };
        if ptr.is_null() { None } else { Some(Self(ptr)) }
    }
}

impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SysAllocString で割り当てた BSTR を解放する。
            unsafe {
                SysFreeString(self.0);
            }
        }
    }
}

fn format_announcement_text(text: &str) -> String {
    let normalized: String = text
        .chars()
        .map(|ch| match ch {
            '\r' | '\n' | '\t' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .take(MAX_ANNOUNCE_CHARS)
        .collect();
    normalized.trim().to_string()
}

pub(crate) fn announce_uia_notification(hwnd: HWND, text: &str) {
    if hwnd.is_null() {
        return;
    }
    let clean = format_announcement_text(text);
    if clean.is_empty() {
        return;
    }
    let Some(api) = load_uia_api() else {
        return;
    };
    // SAFETY: UIA クライアントが待機中かを確認し、待機時のみホストプロバイダ経由で通知を発火する。
    unsafe {
        if (api.clients_are_listening)() == 0 {
            return;
        }
        let mut provider: *mut c_void = std::ptr::null_mut();
        if (api.host_provider_from_hwnd)(hwnd, &mut provider) != S_OK || provider.is_null() {
            return;
        }
        let _guard = ProviderGuard(provider);
        let Some(display) = Bstr::new(&clean) else {
            return;
        };
        let Some(activity_id) = Bstr::new("ZeroHop.IncomingMessage") else {
            return;
        };
        let _ = (api.raise_notification_event)(
            provider,
            NOTIFICATION_KIND_ACTION_COMPLETED,
            NOTIFICATION_PROCESSING_MOST_RECENT,
            display.0,
            activity_id.0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_announcement_text_strips_controls_and_truncates() {
        let raw = "Alice:\r\nこんにちは\tテスト\x07";
        assert_eq!(format_announcement_text(raw), "Alice:  こんにちは テスト");

        let long = "あ".repeat(MAX_ANNOUNCE_CHARS + 50);
        assert_eq!(
            format_announcement_text(&long).chars().count(),
            MAX_ANNOUNCE_CHARS
        );
    }

    #[test]
    fn announce_uia_notification_noop_on_null_hwnd_or_empty() {
        announce_uia_notification(std::ptr::null_mut(), "test");
        announce_uia_notification(std::ptr::null_mut(), "");
    }
}
