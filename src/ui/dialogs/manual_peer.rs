use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, ES_AUTOHSCROLL, ES_NUMBER, IDCANCEL, IDOK, SetWindowTextW,
};

use zerohop::domain::validation::{ValidationError, validate_manual_peer_endpoint};

use super::{
    ModalHandler, ModalSignal, create_button, create_edit, create_static, run_modal_dialog,
};
use crate::ui::a11y::set_cue_banner;
use crate::ui::theme::scale_dpi;
use crate::ui::{read_window_text, to_wide};

const IDC_DLG_PEER_IP: usize = 4201;
const IDC_DLG_PEER_PORT: usize = 4202;
const IDC_DLG_PEER_ERR: usize = 4203;

struct ManualPeerHandler {
    hwnd_ip: HWND,
    hwnd_port: HWND,
    hwnd_err: HWND,
    result: Option<(String, u16)>,
}

impl ModalHandler for ManualPeerHandler {
    fn on_command(&mut self, _dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDOK as usize && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDOK as usize {
            let ip_text = read_window_text(self.hwnd_ip);
            let port_text = read_window_text(self.hwnd_port);
            let parsed_port = port_text.trim().parse::<u16>().unwrap_or(0);
            match validate_manual_peer_endpoint(&ip_text, parsed_port) {
                Ok((ip, port)) => {
                    self.result = Some((ip.to_string(), port));
                    ModalSignal::Close
                }
                Err(err) => {
                    let msg = to_wide(&err.to_string());
                    let focus_target = if matches!(err, ValidationError::InvalidPort) {
                        self.hwnd_port
                    } else {
                        self.hwnd_ip
                    };
                    unsafe {
                        SetWindowTextW(self.hwnd_err, msg.as_ptr());
                        SetFocus(focus_target);
                    }
                    ModalSignal::Continue
                }
            }
        } else if id == IDCANCEL as usize {
            self.result = None;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_add_manual_peer_dialog(
    parent: HWND,
    default_port: u16,
    dpi: u32,
) -> Option<(String, u16)> {
    let port_default = default_port.to_string();
    let res = run_modal_dialog(
        parent,
        "手動ピア追加 - ZeroHop",
        430,
        225,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _lbl_ip = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "相手のIPアドレス(&I):",
                s(16),
                s(14),
                s(380),
                s(20),
            );
            let hwnd_ip = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_IP,
                "",
                ES_AUTOHSCROLL as u32,
                s(16),
                s(36),
                s(380),
                s(26),
            );
            set_cue_banner(hwnd_ip, "例: 192.168.1.50 または 127.0.0.1");

            let _lbl_port = create_static(
                dlg,
                hinst,
                ui_font,
                0,
                "相手のTCP待受ポート番号(&P):",
                s(16),
                s(72),
                s(380),
                s(20),
            );
            let hwnd_port = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_PORT,
                &port_default,
                (ES_AUTOHSCROLL as u32) | (ES_NUMBER as u32),
                s(16),
                s(94),
                s(140),
                s(26),
            );
            let hwnd_err = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_PEER_ERR,
                "",
                s(16),
                s(126),
                s(380),
                s(20),
            );
            let _btn_ok = create_button(
                dlg,
                hinst,
                ui_font,
                IDOK as usize,
                "接続して追加(&A)",
                true,
                s(160),
                s(150),
                s(132),
                s(30),
            );
            let _btn_cancel = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "キャンセル",
                false,
                s(302),
                s(150),
                s(94),
                s(30),
            );
            (
                ManualPeerHandler {
                    hwnd_ip,
                    hwnd_port,
                    hwnd_err,
                    result: None,
                },
                hwnd_ip,
            )
        },
    );
    res.result
}
