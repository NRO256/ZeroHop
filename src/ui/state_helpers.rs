//! スレッドローカル状態管理・6ヘルパー集約パターン・WndProc パニック境界保護。

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::HMENU;
use zeroize::{Zeroize, Zeroizing};

use lan_messenger::app::coordinator::SessionLogReader;
use lan_messenger::app::state::{AppEvent, AppStateKind, UiCommand};
use lan_messenger::domain::model::{PeerView, ThreadKey, UserStatus};
use lan_messenger::network::nic::NicInfo;
use lan_messenger::storage::config::LocalConfig;
use lan_messenger::storage::paths::AppPaths;

use super::sound::SoundController;
use super::theme::ThemeResources;

pub(crate) struct UiHandles {
    pub hmenu_main: HMENU,
    pub hmenu_status: HMENU,
    pub theme: ThemeResources,

    // ログイン画面コントロール群
    pub login_title: HWND,
    pub login_subtitle: HWND,
    pub login_name_label: HWND,
    pub login_name_edit: HWND,
    pub login_pass_label: HWND,
    pub login_pass_edit: HWND,
    pub login_pass_guide: HWND,
    pub login_show_pass: HWND,
    pub login_submit: HWND,
    pub login_cancel: HWND,
    pub login_options: HWND,
    pub login_status: HWND,

    // メイン画面コントロール群
    pub main_peer_label: HWND,
    pub main_peer_list: HWND,
    pub main_thread_header: HWND,
    pub main_notice: HWND,
    pub main_chat_list: HWND,
    pub main_byte_guide: HWND,
    pub main_input_edit: HWND,
    pub main_send_btn: HWND,
    pub main_statusbar: HWND,

    // ロック画面コントロール群 (Phase 2)
    pub lock_title: HWND,
    pub lock_guide: HWND,
    pub lock_pass_label: HWND,
    pub lock_pass_edit: HWND,
    pub lock_unlock_btn: HWND,
    pub lock_logout_btn: HWND,
    pub lock_status: HWND,
}

impl UiHandles {
    pub fn login_controls(&self) -> [HWND; 12] {
        [
            self.login_title,
            self.login_subtitle,
            self.login_name_label,
            self.login_name_edit,
            self.login_pass_label,
            self.login_pass_edit,
            self.login_pass_guide,
            self.login_show_pass,
            self.login_submit,
            self.login_cancel,
            self.login_options,
            self.login_status,
        ]
    }

    pub fn main_controls(&self) -> [HWND; 9] {
        [
            self.main_peer_label,
            self.main_peer_list,
            self.main_thread_header,
            self.main_notice,
            self.main_chat_list,
            self.main_byte_guide,
            self.main_input_edit,
            self.main_send_btn,
            self.main_statusbar,
        ]
    }

    pub fn lock_controls(&self) -> [HWND; 7] {
        [
            self.lock_title,
            self.lock_guide,
            self.lock_pass_label,
            self.lock_pass_edit,
            self.lock_unlock_btn,
            self.lock_logout_btn,
            self.lock_status,
        ]
    }

    pub fn all_ui_font_controls(&self) -> [HWND; 25] {
        [
            self.login_subtitle,
            self.login_name_label,
            self.login_name_edit,
            self.login_pass_label,
            self.login_pass_edit,
            self.login_pass_guide,
            self.login_show_pass,
            self.login_submit,
            self.login_cancel,
            self.login_options,
            self.login_status,
            self.main_peer_label,
            self.main_peer_list,
            self.main_notice,
            self.main_chat_list,
            self.main_byte_guide,
            self.main_input_edit,
            self.main_send_btn,
            self.main_statusbar,
            self.lock_guide,
            self.lock_pass_label,
            self.lock_pass_edit,
            self.lock_unlock_btn,
            self.lock_logout_btn,
            self.lock_status,
        ]
    }
}

pub(crate) struct UiState {
    pub app_state: AppStateKind,
    pub paths: AppPaths,
    pub config: LocalConfig,
    pub cmd_tx: mpsc::Sender<UiCommand>,
    pub log_reader: SessionLogReader,
    pub event_rx: std::sync::mpsc::Receiver<AppEvent>,
    pub active_thread: ThreadKey,
    pub peers: Vec<PeerView>,
    pub display_name: String,
    pub room_code: String,
    pub ephemeral_peer_id: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub nic_info: Option<NicInfo>,
    pub status: UserStatus,
    pub total_log_bytes: usize,
    pub last_lv_count: usize,
    pub notice_text: String,
    pub dpi: u32,
    pub high_contrast: bool,
    pub modal_open: bool,
    pub last_focus: HWND,
    pub window_alive: Arc<AtomicBool>,
    pub multi_instance: bool,
    pub sound: SoundController,
    pub broadcast_unread_count: usize,
    pub unread_by_peer: HashMap<String, usize>,
    pub last_search_query: Zeroizing<String>,
    pub auto_away_triggered: bool,
    pub tray_icon_added: bool,
}

impl UiState {
    pub fn clear_session_fields(&mut self) {
        self.display_name.zeroize();
        self.room_code.zeroize();
        self.ephemeral_peer_id.zeroize();
        for p in &mut self.peers {
            p.peer_id.zeroize();
            p.display_name.zeroize();
        }
        self.peers.clear();
        self.notice_text.zeroize();
        self.active_thread = ThreadKey::Broadcast;
        self.tcp_port = 0;
        self.udp_port = 0;
        self.nic_info = None;
        self.status = UserStatus::Online;
        self.total_log_bytes = 0;
        self.last_lv_count = 0;
        self.last_focus = null_mut();
        self.sound.mark_logout();
        self.broadcast_unread_count = 0;
        for (mut pid, _) in self.unread_by_peer.drain() {
            pid.zeroize();
        }
        self.last_search_query.zeroize();
        self.auto_away_triggered = false;
    }
}

thread_local! {
    static UI_HANDLES: RefCell<Option<UiHandles>> = const { RefCell::new(None) };
    static UI_STATE: RefCell<Option<UiState>> = const { RefCell::new(None) };
}

pub(crate) fn init_thread_locals(handles: UiHandles, state: UiState) {
    UI_HANDLES.with(|cell| {
        *cell.borrow_mut() = Some(handles);
    });
    UI_STATE.with(|cell| {
        *cell.borrow_mut() = Some(state);
    });
}

pub(crate) fn clear_thread_locals() {
    UI_STATE.with(|cell| {
        if let Ok(mut guard) = cell.try_borrow_mut()
            && let Some(mut state) = guard.take()
        {
            state.clear_session_fields();
        }
    });
    UI_HANDLES.with(|cell| {
        if let Ok(mut guard) = cell.try_borrow_mut() {
            *guard = None;
        }
    });
}

pub(crate) fn with_ui<R>(f: impl FnOnce(&UiHandles) -> R) -> Option<R> {
    UI_HANDLES.with(|cell| cell.try_borrow().ok().and_then(|g| g.as_ref().map(f)))
}

pub(crate) fn with_ui_mut<R>(f: impl FnOnce(&mut UiHandles) -> R) -> Option<R> {
    UI_HANDLES.with(|cell| {
        cell.try_borrow_mut()
            .ok()
            .and_then(|mut g| g.as_mut().map(f))
    })
}

pub(crate) fn with_state<R>(f: impl FnOnce(&UiState) -> R) -> Option<R> {
    UI_STATE.with(|cell| cell.try_borrow().ok().and_then(|g| g.as_ref().map(f)))
}

pub(crate) fn with_state_mut<R>(f: impl FnOnce(&mut UiState) -> R) -> Option<R> {
    UI_STATE.with(|cell| {
        cell.try_borrow_mut()
            .ok()
            .and_then(|mut g| g.as_mut().map(f))
    })
}

pub(crate) fn with_ui_and_state<R>(f: impl FnOnce(&UiHandles, &UiState) -> R) -> Option<R> {
    with_ui(|h| with_state(|s| f(h, s))).flatten()
}

pub(crate) fn with_ui_and_state_mut<R>(
    f: impl FnOnce(&mut UiHandles, &mut UiState) -> R,
) -> Option<R> {
    with_ui_mut(|h| with_state_mut(|s| f(h, s))).flatten()
}

pub(crate) fn guard_wnd_proc<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
}
