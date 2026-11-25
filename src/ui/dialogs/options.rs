use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, CBS_DROPDOWNLIST, CreateWindowExW,
    ES_AUTOHSCROLL, ES_NUMBER, IDCANCEL, IDOK, SendMessageW, SetWindowTextW, WM_SETFONT, WS_CHILD,
    WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

use zerohop::domain::model::{MAX_MAX_MEMORY_MB, MIN_MAX_MEMORY_MB};
use zerohop::network::nic::{NicCandidate, discover_ipv4_nics};
use zerohop::storage::config::LocalConfig;
use zerohop::storage::paths::AppPaths;

use super::{
    ModalHandler, ModalSignal, create_button, create_checkbox, create_edit, create_static,
    is_checked, run_modal_dialog,
};
use crate::ui::theme::scale_dpi;
use crate::ui::{read_window_text, to_wide};

const IDC_DLG_OPT_NIC: usize = 4301;
const IDC_DLG_OPT_UDP: usize = 4302;
const IDC_DLG_OPT_TCP: usize = 4303;
const IDC_DLG_OPT_MEM: usize = 4304;
const IDC_DLG_OPT_ERR: usize = 4305;
const IDC_DLG_OPT_AWAY: usize = 4306;
const IDC_DLG_OPT_SOUND_MASTER: usize = 4307;
const IDC_DLG_OPT_SOUND_LOGIN: usize = 4308;
const IDC_DLG_OPT_SOUND_PEER: usize = 4309;
const IDC_DLG_OPT_SOUND_MSG: usize = 4310;
const IDC_DLG_OPT_SEND_ENTER: usize = 4311;
const IDC_DLG_OPT_HIDE_PREVIEW: usize = 4312;
const IDC_DLG_OPT_LOCK_LOGOUT: usize = 4313;
const IDC_DLG_OPT_UIA_ANNOUNCE: usize = 4314;

fn parse_u16_in_range(
    hwnd_field: HWND,
    hwnd_err: HWND,
    min: u16,
    max: u16,
    label: &str,
    unit: &str,
) -> Option<u16> {
    let raw = read_window_text(hwnd_field);
    let parsed = raw.trim().parse::<u16>().ok();
    match parsed {
        Some(v) if (min..=max).contains(&v) => Some(v),
        _ => {
            let msg = to_wide(&format!(
                "{label}は {min}〜{max}{unit} の範囲で指定してください。"
            ));
            unsafe {
                SetWindowTextW(hwnd_err, msg.as_ptr());
                SetFocus(hwnd_field);
            }
            None
        }
    }
}

struct OptionsHandler {
    current_cfg: LocalConfig,
    nics: Vec<NicCandidate>,
    hwnd_nic: HWND,
    hwnd_udp: HWND,
    hwnd_tcp: HWND,
    hwnd_mem: HWND,
    hwnd_away: HWND,
    hwnd_lock_logout: HWND,
    hwnd_sound_master: HWND,
    hwnd_sound_login: HWND,
    hwnd_sound_peer: HWND,
    hwnd_sound_msg: HWND,
    hwnd_send_enter: HWND,
    hwnd_hide_preview: HWND,
    hwnd_uia_announce: HWND,
    hwnd_err: HWND,
    result: Option<LocalConfig>,
}

impl ModalHandler for OptionsHandler {
    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDOK as usize {
            let Some(udp_port) =
                parse_u16_in_range(self.hwnd_udp, self.hwnd_err, 1, u16::MAX, "UDPポート", "")
            else {
                return ModalSignal::Continue;
            };
            let Some(tcp_port) =
                parse_u16_in_range(self.hwnd_tcp, self.hwnd_err, 1, u16::MAX, "TCPポート", "")
            else {
                return ModalSignal::Continue;
            };
            let Some(mem_mb) = parse_u16_in_range(
                self.hwnd_mem,
                self.hwnd_err,
                MIN_MAX_MEMORY_MB,
                MAX_MAX_MEMORY_MB,
                "会話メモリ上限",
                " MiB",
            ) else {
                return ModalSignal::Continue;
            };
            let Some(away_mins) =
                parse_u16_in_range(self.hwnd_away, self.hwnd_err, 0, 60, "自動離席時間", " 分")
            else {
                return ModalSignal::Continue;
            };
            let Some(lock_logout_mins) = parse_u16_in_range(
                self.hwnd_lock_logout,
                self.hwnd_err,
                0,
                240,
                "ロック中自動ログアウト",
                " 分",
            ) else {
                return ModalSignal::Continue;
            };

            let sel = unsafe { SendMessageW(self.hwnd_nic, CB_GETCURSEL, 0, 0) };
            let preferred_nic_ip = if sel > 0 {
                self.nics.get((sel as usize) - 1).map(|n| n.ip.to_string())
            } else {
                None
            };

            let mut next = self.current_cfg.clone();
            next.udp_port = udp_port;
            next.tcp_port = tcp_port;
            next.max_memory_mb = mem_mb;
            next.preferred_nic_ip = preferred_nic_ip;
            next.auto_away_minutes = away_mins;
            next.auto_logout_on_lock_minutes = lock_logout_mins;
            next.sound_enabled = is_checked(self.hwnd_sound_master);
            next.sound_on_login_logout = is_checked(self.hwnd_sound_login);
            next.sound_on_peer_presence = is_checked(self.hwnd_sound_peer);
            next.sound_on_message = is_checked(self.hwnd_sound_msg);
            next.send_on_enter = is_checked(self.hwnd_send_enter);
            next.hide_notification_preview = is_checked(self.hwnd_hide_preview);
            next.uia_announce_incoming = is_checked(self.hwnd_uia_announce);
            next.sanitize();
            self.result = Some(next);
            ModalSignal::Close
        } else if id == IDCANCEL as usize {
            self.result = None;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_options_dialog(
    parent: HWND,
    current_cfg: &LocalConfig,
    paths: &AppPaths,
    dpi: u32,
) -> Option<LocalConfig> {
    let nics = discover_ipv4_nics();
    let writable = paths.is_base_dir_writable();
    let persist_note = if writable {
        "設定は config.json に保存されます（表示名・パスワード・履歴は保存しません）。"
    } else {
        "読み取り専用フォルダのため設定ファイルは書き込まれず、このセッションのみ反映されます。"
    };
    let cfg_clone = current_cfg.clone();

    let res = run_modal_dialog(
        parent,
        "オプション設定 - ZeroHop",
        520,
        604,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl_nic = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "使用ネットワークアダプタ (NIC)(&N):",
                s(16),
                s(14),
                s(452),
                s(20),
            );
            let cb_cls = to_wide("COMBOBOX");
            let hwnd_nic = unsafe {
                CreateWindowExW(
                    0,
                    cb_cls.as_ptr(),
                    null(),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | (CBS_DROPDOWNLIST as u32),
                    s(16),
                    s(36),
                    s(452),
                    s(200),
                    dlg,
                    IDC_DLG_OPT_NIC as _,
                    hinst,
                    null_mut(),
                )
            };
            unsafe {
                SendMessageW(hwnd_nic, WM_SETFONT, ui_font as usize, 1);
                let auto_w = to_wide("自動選択（物理NIC優先）");
                SendMessageW(hwnd_nic, CB_ADDSTRING, 0, auto_w.as_ptr() as LPARAM);
                let mut selected_idx: usize = 0;
                for (i, nic) in nics.iter().enumerate() {
                    let vtag = if nic.is_virtual { " [仮想]" } else { "" };
                    let label = format!("{} ({}){vtag}", nic.friendly_name, nic.ip);
                    let w = to_wide(&label);
                    SendMessageW(hwnd_nic, CB_ADDSTRING, 0, w.as_ptr() as LPARAM);
                    if cfg_clone.preferred_nic_ip.as_deref() == Some(&nic.ip.to_string()) {
                        selected_idx = i + 1;
                    }
                }
                SendMessageW(hwnd_nic, CB_SETCURSEL, selected_idx, 0);
            }

            let _lbl_udp = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "UDP 検出ポート(&U):",
                s(16),
                s(74),
                s(210),
                s(20),
            );
            let hwnd_udp = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_UDP,
                &cfg_clone.udp_port.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(96),
                s(160),
                s(26),
            );

            let _lbl_tcp = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "TCP 通信ポート(&T):",
                s(240),
                s(74),
                s(210),
                s(20),
            );
            let hwnd_tcp = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_TCP,
                &cfg_clone.tcp_port.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(240),
                s(96),
                s(160),
                s(26),
            );

            let _lbl_mem = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "会話メモリ上限 (4〜32 MiB)(&M):",
                s(16),
                s(134),
                s(220),
                s(20),
            );
            let hwnd_mem = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_MEM,
                &cfg_clone.max_memory_mb.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(156),
                s(120),
                s(26),
            );

            let _lbl_away = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "自動離席 (分, 0で無効)(&A):",
                s(240),
                s(134),
                s(240),
                s(20),
            );
            let hwnd_away = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_AWAY,
                &cfg_clone.auto_away_minutes.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(240),
                s(156),
                s(120),
                s(26),
            );

            let _lbl_lock_logout = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "ロック中自動ログアウト (分, 0で無効)(&L):",
                s(16),
                s(192),
                s(280),
                s(20),
            );
            let hwnd_lock_logout = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_LOCK_LOGOUT,
                &cfg_clone.auto_logout_on_lock_minutes.to_string(),
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(214),
                s(120),
                s(26),
            );

            let hwnd_sound_master = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_MASTER,
                "効果音・通知音を有効にする(&S)",
                cfg_clone.sound_enabled,
                s(16),
                s(252),
                s(468),
                s(22),
            );
            let hwnd_sound_login = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_LOGIN,
                "ログイン・ログアウト／終了音を鳴らす",
                cfg_clone.sound_on_login_logout,
                s(34),
                s(278),
                s(450),
                s(22),
            );
            let hwnd_sound_peer = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_PEER,
                "他ピアの参加・退出音を鳴らす",
                cfg_clone.sound_on_peer_presence,
                s(34),
                s(304),
                s(450),
                s(22),
            );
            let hwnd_sound_msg = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SOUND_MSG,
                "新着メッセージ通知音を鳴らす",
                cfg_clone.sound_on_message,
                s(34),
                s(330),
                s(450),
                s(22),
            );
            let hwnd_send_enter = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_SEND_ENTER,
                "Enterキーで送信する (Shift+Enterで改行)(&E)",
                cfg_clone.send_on_enter,
                s(16),
                s(360),
                s(468),
                s(22),
            );
            let hwnd_hide_preview = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_HIDE_PREVIEW,
                "新着通知で送信者・本文プレビューを隠す(&P)",
                cfg_clone.hide_notification_preview,
                s(16),
                s(386),
                s(468),
                s(22),
            );
            let hwnd_uia_announce = create_checkbox(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_UIA_ANNOUNCE,
                "新着メッセージをスクリーンリーダーで自動読み上げ(&R)",
                cfg_clone.uia_announce_incoming,
                s(16),
                s(412),
                s(468),
                s(22),
            );

            let _lbl_note = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                persist_note,
                s(16),
                s(446),
                s(472),
                s(34),
            );
            let hwnd_err = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_OPT_ERR,
                "",
                s(16),
                s(486),
                s(472),
                s(20),
            );

            let _btn_ok = create_button(
                dlg,
                hinst,
                ui_font,
                IDOK as usize,
                "保存(&O)",
                true,
                s(278),
                s(520),
                s(100),
                s(30),
            );
            let _btn_cancel = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "キャンセル",
                false,
                s(388),
                s(520),
                s(100),
                s(30),
            );

            (
                OptionsHandler {
                    current_cfg: cfg_clone,
                    nics,
                    hwnd_nic,
                    hwnd_udp,
                    hwnd_tcp,
                    hwnd_mem,
                    hwnd_away,
                    hwnd_lock_logout,
                    hwnd_sound_master,
                    hwnd_sound_login,
                    hwnd_sound_peer,
                    hwnd_sound_msg,
                    hwnd_send_enter,
                    hwnd_hide_preview,
                    hwnd_uia_announce,
                    hwnd_err,
                    result: None,
                },
                hwnd_nic,
            )
        },
    );
    res.result
}
