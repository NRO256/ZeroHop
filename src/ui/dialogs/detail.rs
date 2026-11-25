use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::EM_SETLIMITTEXT;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BN_CLICKED, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, IDCANCEL, SendMessageW, SetWindowTextW,
    WS_BORDER, WS_VSCROLL,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    ModalHandler, ModalSignal, copy_text_to_clipboard, create_button, create_edit, create_static,
    run_modal_dialog,
};
use crate::ui::theme::scale_dpi;
use crate::ui::{normalize_crlf, to_wide};

const IDC_DLG_DETAIL_META: usize = 4101;
const IDC_DLG_DETAIL_BODY: usize = 4102;
const IDC_DLG_DETAIL_COPY: usize = 4103;
const IDC_DLG_DETAIL_RETRY: usize = 4104;
const IDC_DLG_DETAIL_STATUS: usize = 4105;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct DetailDialogInput {
    pub sender_name: String,
    pub time_text: String,
    pub status_text: String,
    pub body: String,
    #[zeroize(skip)]
    pub can_retry: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetailDialogAction {
    Closed,
    Retry,
}

struct DetailHandler {
    body: Zeroizing<String>,
    can_retry: bool,
    hwnd_status: HWND,
    action: DetailDialogAction,
}

impl ModalHandler for DetailHandler {
    fn default_button_id(&self) -> i32 {
        IDCANCEL
    }

    fn on_command(&mut self, dlg: HWND, id: usize, code: u32) -> ModalSignal {
        if code != BN_CLICKED && id != IDCANCEL as usize {
            return ModalSignal::Continue;
        }
        if id == IDC_DLG_DETAIL_COPY {
            let msg = if copy_text_to_clipboard(dlg, &self.body) {
                "メッセージ本文をクリップボードへコピーしました。"
            } else {
                "クリップボードへのコピーに失敗しました。"
            };
            let w = to_wide(msg);
            unsafe {
                SetWindowTextW(self.hwnd_status, w.as_ptr());
            }
            ModalSignal::Continue
        } else if id == IDC_DLG_DETAIL_RETRY && self.can_retry {
            self.action = DetailDialogAction::Retry;
            ModalSignal::Close
        } else if id == IDCANCEL as usize {
            self.action = DetailDialogAction::Closed;
            ModalSignal::Close
        } else {
            ModalSignal::Continue
        }
    }
}

pub(crate) fn show_message_detail_dialog(
    parent: HWND,
    detail: &DetailDialogInput,
    dpi: u32,
) -> DetailDialogAction {
    let meta = Zeroizing::new(format!(
        "送信者: {}  |  時刻: {}  |  状態: {}",
        detail.sender_name, detail.time_text, detail.status_text
    ));
    let body_crlf = Zeroizing::new(normalize_crlf(&detail.body));
    let body_clone = Zeroizing::new(detail.body.clone());
    let can_retry = detail.can_retry;

    let res = run_modal_dialog(
        parent,
        "メッセージ全文詳細 - ZeroHop",
        600,
        410,
        dpi,
        |dlg, hinst, ui_font, _| {
            let s = |v| scale_dpi(v, dpi);
            let _meta_lbl = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_META,
                &meta,
                s(16),
                s(12),
                s(552),
                s(22),
            );
            let hwnd_edit = create_edit(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_BODY,
                &body_crlf,
                WS_BORDER
                    | WS_VSCROLL
                    | (ES_MULTILINE as u32)
                    | (ES_AUTOVSCROLL as u32)
                    | (ES_READONLY as u32),
                s(16),
                s(40),
                s(552),
                s(250),
            );
            unsafe {
                SendMessageW(hwnd_edit, EM_SETLIMITTEXT, 0x7FFF_FFFE, 0);
            }
            let hwnd_status = create_static(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_STATUS,
                "Esc キーまたは「閉じる」で会話一覧の選択行へ戻ります。",
                s(16),
                s(298),
                s(552),
                s(20),
            );
            let _btn_copy = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_COPY,
                "本文をコピー(&C)",
                false,
                s(16),
                s(326),
                s(146),
                s(30),
            );
            let btn_retry = create_button(
                dlg,
                hinst,
                ui_font,
                IDC_DLG_DETAIL_RETRY,
                "再送(&R)",
                false,
                s(174),
                s(326),
                s(104),
                s(30),
            );
            if !can_retry {
                unsafe {
                    EnableWindow(btn_retry, 0);
                }
            }
            let _btn_close = create_button(
                dlg,
                hinst,
                ui_font,
                IDCANCEL as usize,
                "閉じる(&X)",
                true,
                s(458),
                s(326),
                s(110),
                s(30),
            );
            (
                DetailHandler {
                    body: body_clone,
                    can_retry,
                    hwnd_status,
                    action: DetailDialogAction::Closed,
                },
                hwnd_edit,
            )
        },
    );
    res.action
}
