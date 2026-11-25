use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, CreateWindowExW, ES_AUTOHSCROLL, IDCANCEL, IDOK, LB_ADDSTRING, LB_GETCURSEL,
    LB_RESETCONTENT, LBN_DBLCLK, LBS_NOINTEGRALHEIGHT, LBS_NOTIFY, SendMessageW, SetWindowTextW,
    WM_SETFONT, WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use zeroize::{Zeroize, Zeroizing};

use zerohop::app::coordinator::SessionLogReader;
use zerohop::domain::model::{PeerView, ThreadKey};
use zerohop::domain::session_log::SearchHit;

use super::{
    ModalHandler, ModalSignal, create_button, create_checkbox, create_edit, create_static,
    is_checked, run_modal_dialog,
};
use crate::ui::a11y::set_cue_banner;
use crate::ui::theme::scale_dpi;
use crate::ui::{format_unix_datetime, read_window_text_zeroizing, to_wide};

const IDC_DLG_SEARCH_QUERY: usize = 4501;
const IDC_DLG_SEARCH_CURRENT_ONLY: usize = 4502;
const IDC_DLG_SEARCH_RUN: usize = 4503;
const IDC_DLG_SEARCH_LIST: usize = 4504;
const IDC_DLG_SEARCH_JUMP: usize = 4505;
const IDC_DLG_SEARCH_STATUS: usize = 4506;

pub(crate) struct SearchDialogResult {
    pub last_query: Zeroizing<String>,
    pub jump_target: Option<(ThreadKey, usize)>,
}

struct SearchHandler {
    log_reader: SessionLogReader,
    active_thread: ThreadKey,
    peer_names: Vec<(String, String)>,
    hwnd_query: HWND,
    hwnd_current_only: HWND,
    hwnd_list: HWND,
    hwnd_status: HWND,
    hits: Vec<SearchHit>,
    last_query: Zeroizing<String>,
    jump_target: Option<(ThreadKey, usize)>,
}

impl SearchHandler {
    fn thread_label(&self, thread: &ThreadKey) -> String {
        match thread {
            ThreadKey::Broadcast => "全体チャット".to_string(),
            ThreadKey::Peer(pid) => self
                .peer_names
                .iter()
                .find(|(id, _)| id == pid)
                .map_or_else(|| pid.clone(), |(_, name)| name.clone()),
        }
    }

    fn execute_search(&mut self) {
        let query = read_window_text_zeroizing(self.hwnd_query);
        self.last_query = Zeroizing::new(query.to_string());
        let current_only = is_checked(self.hwnd_current_only);
        let filter = if current_only {
            Some(&self.active_thread)
        } else {
            None
        };

        for mut old in self.hits.drain(..) {
            old.zeroize();
        }
        self.hits = self.log_reader.search(filter, &query, 200);

        unsafe {
            SendMessageW(self.hwnd_list, LB_RESETCONTENT, 0, 0);
            for hit in &self.hits {
                let thread_lbl = self.thread_label(&hit.thread);
                let time_lbl = format_unix_datetime(hit.timestamp);
                let line = format!(
                    "[{thread_lbl}] {time_lbl} {}: {}",
                    hit.sender_name, hit.preview
                );
                let line_w = to_wide(&line);
                SendMessageW(self.hwnd_list, LB_ADDSTRING, 0, line_w.as_ptr() as LPARAM);
            }
            let status_msg = if query.trim().is_empty() {
                "検索キーワードを入力してください。".to_string()
            } else if self.hits.is_empty() {
                "一致するメッセージは見つかりませんでした。".to_string()
            } else {
                format!(
                    "{} 件見つかりました（上下キーまたはダブルクリックで移動）。",
                    self.hits.len()
                )
            };
            let status_w = to_wide(&status_msg);
            SetWindowTextW(self.hwnd_status, status_w.as_ptr());
        }
    }

    fn select_current_and_close(&mut self) -> ModalSignal {
        let idx = unsafe { SendMessageW(self.hwnd_list, LB_GETCURSEL, 0, 0) };
        if idx >= 0
            && let Some(hit) = self.hits.get(idx as usize)
        {
            self.jump_target = Some((hit.thread.clone(), hit.index));
            return ModalSignal::Close;
        }
        let msg = to_wide("移動先の検索結果を選択してください。");
        unsafe { SetWindowTextW(self.hwnd_status, msg.as_ptr()) };
        ModalSignal::Continue
    }
}

impl Drop for SearchHandler {
    fn drop(&mut self) {
        for mut h in self.hits.drain(..) {
            h.zeroize();
        }
    }
}

impl ModalHandler for SearchHandler {
    fn default_button_id(&self) -> i32 {
        IDC_DLG_SEARCH_RUN as i32
    }

    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if id == IDC_DLG_SEARCH_LIST && code == LBN_DBLCLK {
            return self.select_current_and_close();
        }
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDC_DLG_SEARCH_RUN || id == IDOK as usize {
            self.execute_search();
            ModalSignal::Continue
        } else if id == IDC_DLG_SEARCH_JUMP {
            self.select_current_and_close()
        } else if id == IDCANCEL as usize {
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_search_dialog(
    parent: HWND,
    log_reader: SessionLogReader,
    active_thread: ThreadKey,
    peers: &[PeerView],
    initial_query: &str,
    dpi: u32,
) -> SearchDialogResult {
    let peer_names: Vec<(String, String)> = peers
        .iter()
        .map(|p| (p.peer_id.clone(), p.display_name.clone()))
        .collect();
    let initial_q = initial_query.to_string();

    let mut res = run_modal_dialog(
        parent,
        "セッション内メッセージ検索 - ZeroHop",
        620,
        430,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "検索キーワード(&K):",
                s(16),
                s(14),
                s(572),
                s(20),
            );
            let hwnd_query = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_QUERY,
                &initial_q,
                ES_AUTOHSCROLL as u32,
                s(16),
                s(38),
                s(460),
                s(26),
            );
            set_cue_banner(hwnd_query, "キーワード（送信者名または本文）");

            let _btn_run = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_RUN,
                "検索(&S)",
                true,
                s(486),
                s(36),
                s(102),
                s(30),
            );

            let hwnd_current_only = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_CURRENT_ONLY,
                "現在表示中の会話のみ検索(&T)",
                false,
                s(16),
                s(72),
                s(572),
                s(22),
            );

            let lb_cls = to_wide("LISTBOX");
            let hwnd_list = unsafe {
                let h = CreateWindowExW(
                    WS_EX_CLIENTEDGE,
                    lb_cls.as_ptr(),
                    null(),
                    WS_CHILD
                        | WS_VISIBLE
                        | WS_TABSTOP
                        | WS_VSCROLL
                        | WS_BORDER
                        | (LBS_NOTIFY as u32)
                        | (LBS_NOINTEGRALHEIGHT as u32),
                    s(16),
                    s(102),
                    s(572),
                    s(210),
                    dlg,
                    IDC_DLG_SEARCH_LIST as _,
                    hinst,
                    null_mut(),
                );
                SendMessageW(h, WM_SETFONT, ui_font as usize, 1);
                h
            };

            let hwnd_status = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_STATUS,
                "キーワードを入力して「検索」を押してください。",
                s(16),
                s(320),
                s(572),
                s(20),
            );

            let _btn_jump = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_SEARCH_JUMP,
                "選択位置へ移動(&J)",
                false,
                s(340),
                s(348),
                s(140),
                s(30),
            );
            let _btn_close = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "閉じる(&C)",
                false,
                s(488),
                s(348),
                s(100),
                s(30),
            );

            let mut handler = SearchHandler {
                log_reader,
                active_thread,
                peer_names,
                hwnd_query,
                hwnd_current_only,
                hwnd_list,
                hwnd_status,
                hits: Vec::new(),
                last_query: Zeroizing::new(initial_q.clone()),
                jump_target: None,
            };
            if !initial_q.trim().is_empty() {
                handler.execute_search();
            }
            (handler, hwnd_query)
        },
    );

    SearchDialogResult {
        last_query: std::mem::take(&mut res.last_query),
        jump_target: res.jump_target.take(),
    }
}
