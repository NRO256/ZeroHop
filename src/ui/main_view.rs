//! メイン画面（接続先リスト・仮想 ListView 会話一覧・入力欄・4区画ステータスバー・詳細表示・再送）。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{ClientToScreen, HFONT, InvalidateRect};
use windows_sys::Win32::System::SystemServices::{SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::{
    EM_REPLACESEL, EM_SETLIMITTEXT, EM_SETSEL, LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH,
    LVCFMT_LEFT, LVCOLUMNW, LVIF_TEXT, LVIR_BOUNDS, LVM_ENSUREVISIBLE, LVM_GETITEMRECT,
    LVM_INSERTCOLUMNW, LVM_REDRAWITEMS, LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE,
    LVM_SETITEMCOUNT, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_OWNERDATA, LVS_REPORT,
    LVS_SHOWSELALWAYS, LVS_SINGLESEL, LVSICF_NOSCROLL, NMLVDISPINFOW, SB_SETPARTS, SB_SETTEXTW,
    STATUSCLASSNAMEW, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, VK_CONTROL, VK_ESCAPE, VK_MENU, VK_RETURN, VK_SHIFT,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, BS_PUSHBUTTON, CreatePopupMenu, CreateWindowExW, DLGC_WANTMESSAGE, DestroyMenu,
    ES_AUTOHSCROLL, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, ES_WANTRETURN, GWL_STYLE,
    GetClientRect, GetParent, GetWindowLongPtrW, GetWindowRect, LB_ADDSTRING, LB_GETCURSEL,
    LB_RESETCONTENT, LB_SETCURSEL, LBS_NOINTEGRALHEIGHT, LBS_NOTIFY, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MSG, MoveWindow, PostMessageW, SW_HIDE, SW_SHOW, SendMessageW, SetWindowTextW,
    ShowWindow, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_TOPALIGN, TrackPopupMenu, WM_CHAR, WM_COMMAND,
    WM_GETDLGCODE, WM_IME_ENDCOMPOSITION, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_KEYUP,
    WM_KILLFOCUS, WM_SETFONT, WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VISIBLE,
    WS_VSCROLL,
};
use zeroize::{Zeroize, Zeroizing};

use zerohop::app::coordinator::TryReadMessage;
use zerohop::app::state::{AppStateKind, UiCommand};
use zerohop::domain::model::{DeliveryState, ReplyReference, ThreadKey};
use zerohop::domain::validation::{contains_mention, sanitize_reply_preview, validate_chat_body};

use super::a11y::{
    focus_control, focus_listview_item, get_selected_listview_index, set_cue_banner,
};
use super::dialogs::{
    DetailDialogAction, DetailDialogInput, confirm_delete_message, copy_text_to_clipboard,
    pick_save_text_log_dialog, show_message_detail_dialog,
};
use super::state_helpers::{
    UiHandles, UiState, with_state_mut, with_ui, with_ui_and_state, with_ui_and_state_mut,
};
use super::theme::{apply_listview_explorer_theme, scale_dpi};
use super::transfer_ui::{process_pending_file_offers, sync_file_transfer_button};
use super::{
    IDC_MAIN_CHAT_LIST, IDC_MAIN_FILE_BTN, IDC_MAIN_INPUT_EDIT, IDC_MAIN_NOTICE,
    IDC_MAIN_PEER_LABEL, IDC_MAIN_PEER_LIST, IDC_MAIN_REPLY_CLEAR_BTN, IDC_MAIN_REPLY_LABEL,
    IDC_MAIN_SEND_BTN, IDC_MAIN_STATUSBAR, IDC_MAIN_THREAD_HEADER, WM_APP_OPEN_DETAIL,
    default_chat_log_filename, format_chat_log_export_text, format_unix_datetime,
    format_unix_time_hms, is_message_retryable, make_child_control, read_window_text_zeroizing,
    resolve_migrated_thread, summarize_message_body, to_wide, write_utf16_buf,
};

const SUBCLASS_ID_CHAT_LIST: usize = 201;
const SUBCLASS_ID_INPUT_EDIT: usize = 202;

static INPUT_SEND_ON_ENTER: AtomicBool = AtomicBool::new(true);

pub(crate) fn set_input_send_on_enter(hwnd_input: HWND, enabled: bool) {
    INPUT_SEND_ON_ENTER.store(enabled, Ordering::Relaxed);
    if !hwnd_input.is_null() {
        let cue = if enabled {
            "メッセージを入力 (Enter で送信 / Shift+Enter で改行)"
        } else {
            "メッセージを入力 (Ctrl+Enter で送信)"
        };
        set_cue_banner(hwnd_input, cue);
    }
}

pub(crate) struct MainControlHandles {
    pub peer_label: HWND,
    pub peer_list: HWND,
    pub thread_header: HWND,
    pub notice: HWND,
    pub chat_list: HWND,
    pub reply_label: HWND,
    pub reply_clear_btn: HWND,
    pub input_edit: HWND,
    pub send_btn: HWND,
    pub file_btn: HWND,
    pub statusbar: HWND,
}

fn insert_column(hwnd_lv: HWND, index: i32, title: &str, width: i32) {
    let mut title_w = to_wide(title);
    let col = LVCOLUMNW {
        mask: LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM,
        fmt: LVCFMT_LEFT,
        cx: width,
        pszText: title_w.as_mut_ptr(),
        cchTextMax: 0,
        iSubItem: index,
        iImage: 0,
        iOrder: 0,
        cxMin: 0,
        cxDefault: 0,
        cxIdeal: 0,
    };
    unsafe {
        SendMessageW(
            hwnd_lv,
            LVM_INSERTCOLUMNW,
            index as usize,
            (&raw const col) as LPARAM,
        );
    }
}

unsafe extern "system" fn chat_list_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _uid: usize,
    ref_data: usize,
) -> LRESULT {
    let res = catch_unwind(AssertUnwindSafe(|| unsafe {
        if msg == WM_GETDLGCODE && lparam != 0 {
            let m = &*(lparam as *const MSG);
            if m.message == WM_KEYDOWN && m.wParam == usize::from(VK_RETURN) {
                return DLGC_WANTMESSAGE as LRESULT;
            }
        }
        if msg == WM_KEYDOWN && wparam == usize::from(VK_RETURN) {
            let parent = ref_data as HWND;
            if !parent.is_null() {
                PostMessageW(parent, WM_APP_OPEN_DETAIL, 0, 0);
                return 0;
            }
        }
        DefSubclassProc(hwnd, msg, wparam, lparam)
    }));
    res.unwrap_or(0)
}

unsafe extern "system" fn input_edit_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _uid: usize,
    ref_data: usize,
) -> LRESULT {
    let res = catch_unwind(AssertUnwindSafe(|| unsafe {
        static IME_COMPOSING: AtomicBool = AtomicBool::new(false);
        static SUPPRESS_NEXT_LF: AtomicBool = AtomicBool::new(false);
        static SUPPRESS_NEXT_CR: AtomicBool = AtomicBool::new(false);

        match msg {
            WM_IME_STARTCOMPOSITION => {
                IME_COMPOSING.store(true, Ordering::Relaxed);
            }
            WM_IME_ENDCOMPOSITION => {
                IME_COMPOSING.store(false, Ordering::Relaxed);
            }
            WM_KILLFOCUS => {
                IME_COMPOSING.store(false, Ordering::Relaxed);
                SUPPRESS_NEXT_LF.store(false, Ordering::Relaxed);
                SUPPRESS_NEXT_CR.store(false, Ordering::Relaxed);
            }
            WM_KEYDOWN => {
                let ctrl_down = (GetKeyState(i32::from(VK_CONTROL)) as u16 & 0x8000) != 0;
                let shift_down = (GetKeyState(i32::from(VK_SHIFT)) as u16 & 0x8000) != 0;
                let alt_down = (GetKeyState(i32::from(VK_MENU)) as u16 & 0x8000) != 0;
                let send_on_enter = INPUT_SEND_ON_ENTER.load(Ordering::Relaxed);
                let is_composing = IME_COMPOSING.load(Ordering::Relaxed);

                if wparam == usize::from(VK_RETURN) {
                    if !send_on_enter && ctrl_down && !alt_down {
                        SUPPRESS_NEXT_LF.store(true, Ordering::Relaxed);
                        if !is_composing {
                            let parent = ref_data as HWND;
                            if !parent.is_null() {
                                PostMessageW(
                                    parent,
                                    windows_sys::Win32::UI::WindowsAndMessaging::WM_COMMAND,
                                    IDC_MAIN_SEND_BTN,
                                    hwnd as LPARAM,
                                );
                            }
                        }
                        return 0;
                    }
                    if send_on_enter && !ctrl_down && !shift_down && !alt_down {
                        if is_composing {
                            return DefSubclassProc(hwnd, msg, wparam, lparam);
                        }
                        SUPPRESS_NEXT_CR.store(true, Ordering::Relaxed);
                        let parent = ref_data as HWND;
                        if !parent.is_null() {
                            PostMessageW(
                                parent,
                                windows_sys::Win32::UI::WindowsAndMessaging::WM_COMMAND,
                                IDC_MAIN_SEND_BTN,
                                hwnd as LPARAM,
                            );
                        }
                        return 0;
                    }
                }
                if wparam == usize::from(VK_ESCAPE) && !ctrl_down && !shift_down && !alt_down {
                    let parent = ref_data as HWND;
                    if !parent.is_null() {
                        PostMessageW(parent, WM_COMMAND, IDC_MAIN_REPLY_CLEAR_BTN, hwnd as LPARAM);
                    }
                    return 0;
                }
                if ctrl_down && wparam == b'A' as usize {
                    SendMessageW(hwnd, EM_SETSEL, 0, -1);
                    return 0;
                }
            }
            WM_KEYUP if wparam == usize::from(VK_RETURN) => {
                SUPPRESS_NEXT_LF.store(false, Ordering::Relaxed);
                SUPPRESS_NEXT_CR.store(false, Ordering::Relaxed);
            }
            WM_CHAR => {
                if wparam == 0x0A && SUPPRESS_NEXT_LF.swap(false, Ordering::Relaxed) {
                    return 0;
                }
                if wparam == 0x0D && SUPPRESS_NEXT_CR.swap(false, Ordering::Relaxed) {
                    return 0;
                }
                let ctrl_down = (GetKeyState(i32::from(VK_CONTROL)) as u16 & 0x8000) != 0;
                if ctrl_down && wparam == 0x01 {
                    return 0;
                }
            }
            _ => {}
        }
        DefSubclassProc(hwnd, msg, wparam, lparam)
    }));
    res.unwrap_or(0)
}

pub(crate) fn create_main_controls(
    hwnd_parent: HWND,
    hinst: windows_sys::Win32::Foundation::HANDLE,
    ui_font: HFONT,
    bold_font: HFONT,
    high_contrast: bool,
) -> MainControlHandles {
    let static_w = to_wide("STATIC");
    let listbox_w = to_wide("LISTBOX");
    let edit_w = to_wide("EDIT");
    let button_w = to_wide("BUTTON");

    let static_style = WS_CHILD | SS_LEFT | SS_NOPREFIX;

    let peer_label = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "接続先(&P):",
        0,
        static_style,
        IDC_MAIN_PEER_LABEL,
        ui_font,
    );
    let peer_list = make_child_control(
        hwnd_parent,
        hinst,
        listbox_w.as_ptr(),
        "",
        WS_EX_CLIENTEDGE,
        WS_CHILD
            | WS_BORDER
            | WS_VSCROLL
            | WS_TABSTOP
            | (LBS_NOTIFY as u32)
            | (LBS_NOINTEGRALHEIGHT as u32),
        IDC_MAIN_PEER_LIST,
        ui_font,
    );
    let thread_header = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "全体チャット（全員）",
        0,
        static_style,
        IDC_MAIN_THREAD_HEADER,
        bold_font,
    );
    let notice = make_child_control(
        hwnd_parent,
        hinst,
        edit_w.as_ptr(),
        "",
        WS_EX_CLIENTEDGE,
        WS_CHILD | WS_TABSTOP | (ES_READONLY as u32) | (ES_AUTOHSCROLL as u32),
        IDC_MAIN_NOTICE,
        ui_font,
    );
    let chat_list = unsafe {
        let hwnd = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            null(),
            WS_CHILD
                | WS_BORDER
                | WS_TABSTOP
                | LVS_REPORT
                | LVS_OWNERDATA
                | LVS_SINGLESEL
                | LVS_SHOWSELALWAYS,
            0,
            0,
            100,
            100,
            hwnd_parent,
            IDC_MAIN_CHAT_LIST as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, ui_font as usize, 1);
        SendMessageW(
            hwnd,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as usize,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize,
        );
        apply_listview_explorer_theme(hwnd, high_contrast);
        insert_column(hwnd, 0, "送信者", 110);
        insert_column(hwnd, 1, "メッセージ（Enterで全文）", 340);
        insert_column(hwnd, 2, "時刻", 76);
        insert_column(hwnd, 3, "状態", 110);
        let _ = SetWindowSubclass(
            hwnd,
            Some(chat_list_subclass_proc),
            SUBCLASS_ID_CHAT_LIST,
            hwnd_parent as usize,
        );
        hwnd
    };
    let reply_label = make_child_control(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "",
        0,
        static_style,
        IDC_MAIN_REPLY_LABEL,
        ui_font,
    );
    let reply_clear_btn = make_child_control(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "解除",
        0,
        WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_MAIN_REPLY_CLEAR_BTN,
        ui_font,
    );
    let input_edit = make_child_control(
        hwnd_parent,
        hinst,
        edit_w.as_ptr(),
        "",
        WS_EX_CLIENTEDGE,
        WS_CHILD
            | WS_BORDER
            | WS_VSCROLL
            | WS_TABSTOP
            | (ES_MULTILINE as u32)
            | (ES_WANTRETURN as u32)
            | (ES_AUTOVSCROLL as u32),
        IDC_MAIN_INPUT_EDIT,
        ui_font,
    );
    unsafe {
        SendMessageW(input_edit, EM_SETLIMITTEXT, 16_384, 0);
        let _ = SetWindowSubclass(
            input_edit,
            Some(input_edit_subclass_proc),
            SUBCLASS_ID_INPUT_EDIT,
            hwnd_parent as usize,
        );
    }
    set_cue_banner(
        input_edit,
        "メッセージを入力 (Enter で送信 / Shift+Enter で改行)",
    );

    let send_btn = make_child_control(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "送信(&S)",
        0,
        WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_MAIN_SEND_BTN,
        ui_font,
    );
    let file_btn = make_child_control(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "ファイル(&F)...",
        0,
        WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_MAIN_FILE_BTN,
        ui_font,
    );
    let statusbar = make_child_control(
        hwnd_parent,
        hinst,
        STATUSCLASSNAMEW,
        "",
        0,
        WS_CHILD,
        IDC_MAIN_STATUSBAR,
        ui_font,
    );

    MainControlHandles {
        peer_label,
        peer_list,
        thread_header,
        notice,
        chat_list,
        reply_label,
        reply_clear_btn,
        input_edit,
        send_btn,
        file_btn,
        statusbar,
    }
}

pub(crate) fn remove_main_subclasses(handles: &UiHandles) {
    unsafe {
        if !handles.main_chat_list.is_null() {
            let _ = RemoveWindowSubclass(
                handles.main_chat_list,
                Some(chat_list_subclass_proc),
                SUBCLASS_ID_CHAT_LIST,
            );
        }
        if !handles.main_input_edit.is_null() {
            let _ = RemoveWindowSubclass(
                handles.main_input_edit,
                Some(input_edit_subclass_proc),
                SUBCLASS_ID_INPUT_EDIT,
            );
        }
    }
}

pub(crate) fn layout_main_controls(handles: &UiHandles, client_w: i32, client_h: i32, dpi: u32) {
    let s = |v| scale_dpi(v, dpi);
    let pad = s(10);
    let sb_h = s(26);
    let content_h = (client_h - sb_h - pad * 2).max(s(200));

    let left_w = s(240).min((client_w / 3).max(s(170)));
    let right_x = pad + left_w + pad;
    let right_w = (client_w - right_x - pad).max(s(220));

    unsafe {
        MoveWindow(
            handles.main_statusbar,
            0,
            client_h - sb_h,
            client_w,
            sb_h,
            1,
        );
        let p0 = (client_w * 24) / 100;
        let p1 = (client_w * 42) / 100;
        let p2 = (client_w * 68) / 100;
        let parts = [p0, p1, p2, -1];
        SendMessageW(
            handles.main_statusbar,
            SB_SETPARTS,
            parts.len(),
            parts.as_ptr() as LPARAM,
        );

        let lbl_h = s(22);
        MoveWindow(handles.main_peer_label, pad, pad, left_w, lbl_h, 1);
        MoveWindow(
            handles.main_peer_list,
            pad,
            pad + lbl_h + s(4),
            left_w,
            (content_h - lbl_h - s(4)).max(s(120)),
            1,
        );

        let mut y = pad;
        let hdr_h = s(24);
        MoveWindow(handles.main_thread_header, right_x, y, right_w, hdr_h, 1);
        y += hdr_h + s(4);

        let notice_h = s(26);
        MoveWindow(handles.main_notice, right_x, y, right_w, notice_h, 1);
        y += notice_h + s(6);

        let input_h = s(76);
        let btn_w = s(96);
        let show_reply =
            (GetWindowLongPtrW(handles.main_reply_clear_btn, GWL_STYLE) as u32 & WS_VISIBLE) != 0;
        let reply_h = s(24);
        let reply_total = if show_reply { reply_h + s(4) } else { 0 };
        let list_h = (client_h - sb_h - pad - y - reply_total - input_h - s(6)).max(s(100));

        MoveWindow(handles.main_chat_list, right_x, y, right_w, list_h, 1);
        y += list_h + s(6);

        if show_reply {
            let clear_w = s(64);
            let label_w = (right_w - clear_w - s(6)).max(s(80));
            MoveWindow(
                handles.main_reply_label,
                right_x,
                y + s(3),
                label_w,
                reply_h - s(3),
                1,
            );
            MoveWindow(
                handles.main_reply_clear_btn,
                right_x + label_w + s(6),
                y,
                clear_w,
                reply_h,
                1,
            );
            y += reply_h + s(4);
        }

        let edit_w = (right_w - btn_w - s(8)).max(s(120));
        let send_h = s(44);
        let gap_h = s(4);
        let file_h = (input_h - send_h - gap_h).max(s(24));
        MoveWindow(handles.main_input_edit, right_x, y, edit_w, input_h, 1);
        MoveWindow(
            handles.main_send_btn,
            right_x + edit_w + s(8),
            y,
            btn_w,
            send_h,
            1,
        );
        MoveWindow(
            handles.main_file_btn,
            right_x + edit_w + s(8),
            y + send_h + gap_h,
            btn_w,
            file_h,
            1,
        );

        // 仮想 ListView 列幅の自動配分（送信者 / メッセージ / 時刻 / 状態）
        let col0 = s(108);
        let col2 = s(76);
        let col3 = s(112);
        let col1 = (right_w - col0 - col2 - col3 - s(24)).max(s(140));
        SendMessageW(handles.main_chat_list, LVM_SETCOLUMNWIDTH, 0, col0 as isize);
        SendMessageW(handles.main_chat_list, LVM_SETCOLUMNWIDTH, 1, col1 as isize);
        SendMessageW(handles.main_chat_list, LVM_SETCOLUMNWIDTH, 2, col2 as isize);
        SendMessageW(handles.main_chat_list, LVM_SETCOLUMNWIDTH, 3, col3 as isize);
    }
}

pub(crate) fn show_main_controls(handles: &UiHandles, visible: bool) {
    let cmd = if visible { SW_SHOW } else { SW_HIDE };
    unsafe {
        for hwnd in handles.main_controls() {
            ShowWindow(hwnd, cmd);
        }
        if !visible {
            ShowWindow(handles.main_reply_label, SW_HIDE);
            ShowWindow(handles.main_reply_clear_btn, SW_HIDE);
        }
    }
}

pub(crate) fn sync_reply_bar(hwnd_parent: HWND, handles: &UiHandles, state: &UiState) {
    unsafe {
        if state.app_state == AppStateKind::LoggedIn
            && let Some(reply) = &state.pending_reply
        {
            let text = format!("返信先: {}「{}」", reply.sender_name, reply.preview);
            let w = to_wide(&text);
            SetWindowTextW(handles.main_reply_label, w.as_ptr());
            ShowWindow(handles.main_reply_label, SW_SHOW);
            ShowWindow(handles.main_reply_clear_btn, SW_SHOW);
        } else {
            ShowWindow(handles.main_reply_label, SW_HIDE);
            ShowWindow(handles.main_reply_clear_btn, SW_HIDE);
        }
        if !hwnd_parent.is_null() {
            let mut rc: RECT = std::mem::zeroed();
            if GetClientRect(hwnd_parent, &raw mut rc) != 0 {
                layout_main_controls(handles, rc.right, rc.bottom, state.dpi);
            }
        }
    }
}

pub(crate) fn clear_pending_reply_and_relayout(hwnd_parent: HWND) {
    let target = with_ui_and_state_mut(|handles, state| {
        if state.pending_reply.take().is_some() {
            sync_reply_bar(hwnd_parent, handles, state);
            Some(handles.main_input_edit)
        } else {
            None
        }
    })
    .flatten();
    if let Some(hwnd_input) = target {
        focus_control(hwnd_input);
    }
}

pub(crate) fn set_notice_text(handles: &UiHandles, state: &mut UiState, text: &str) {
    state.notice_text = text.to_string();
    let w = to_wide(text);
    unsafe {
        SetWindowTextW(handles.main_notice, w.as_ptr());
        let _ = InvalidateRect(handles.main_notice, null(), 1);
    }
}

pub(crate) fn update_thread_header(handles: &UiHandles, state: &UiState) {
    let text = match &state.active_thread {
        ThreadKey::Broadcast => {
            let online = state.peers.iter().filter(|p| p.is_online).count();
            format!("全体チャット（全員 / 他オンライン {online}人）")
        }
        ThreadKey::Peer(peer_id) => {
            if let Some(peer) = state.peers.iter().find(|p| &p.peer_id == peer_id) {
                let st = if peer.is_online {
                    peer.status.label_ja()
                } else {
                    "オフライン"
                };
                format!(
                    "1対1チャット: {} [{}] ({}:{}) — {}",
                    peer.display_name, st, peer.ip_text, peer.tcp_port, peer.short_id
                )
            } else {
                "全体チャット（全員）".to_string()
            }
        }
    };
    let w = to_wide(&text);
    unsafe {
        SetWindowTextW(handles.main_thread_header, w.as_ptr());
    }
}

pub(crate) fn update_status_bar(handles: &UiHandles, state: &UiState) {
    let part0 = if state.display_name.is_empty() {
        "未ログイン".to_string()
    } else {
        format!("{} [{}]", state.display_name, state.status.label_ja())
    };
    let part1 = if state.room_code.is_empty() {
        "CODE: ------".to_string()
    } else {
        format!("CODE: {}", state.room_code)
    };
    let online_peers = state.peers.iter().filter(|p| p.is_online).count();
    let part2 = format!(
        "オンライン: {}人",
        online_peers + usize::from(state.app_state == AppStateKind::LoggedIn),
    );
    let part3 = match &state.nic_info {
        Some(nic) => format!("{} ({}:{})", nic.friendly_name, nic.ip, state.tcp_port),
        None if state.tcp_port > 0 => format!("TCP:{} / UDP:{}", state.tcp_port, state.udp_port),
        None => "NIC未接続".to_string(),
    };

    for (idx, text) in [part0, part1, part2, part3].iter().enumerate() {
        let w = to_wide(text);
        unsafe {
            SendMessageW(
                handles.main_statusbar,
                SB_SETTEXTW,
                idx,
                w.as_ptr() as LPARAM,
            );
        }
    }
}

pub(crate) fn clear_unread_for_thread(state: &mut UiState, thread: &ThreadKey) -> bool {
    match thread {
        ThreadKey::Broadcast => {
            let had = state.broadcast_unread_count > 0;
            state.broadcast_unread_count = 0;
            had
        }
        ThreadKey::Peer(pid) => {
            let removed = state.unread_by_peer.remove(pid).unwrap_or(0) > 0;
            for p in &mut state.peers {
                if &p.peer_id == pid {
                    p.unread_count = 0;
                }
            }
            removed
        }
    }
}

pub(crate) fn refresh_peer_list(handles: &UiHandles, state: &mut UiState) -> bool {
    let migrated = resolve_migrated_thread(&state.active_thread, &state.peers);
    let thread_changed = migrated != state.active_thread;
    if thread_changed
        && let ThreadKey::Peer(old_pid) = &state.active_thread
        && let ThreadKey::Peer(new_pid) = &migrated
        && let Some(cnt) = state.unread_by_peer.remove(old_pid)
    {
        *state.unread_by_peer.entry(new_pid.clone()).or_insert(0) += cnt;
    }
    state.active_thread = migrated;

    state
        .unread_by_peer
        .retain(|pid, _| state.peers.iter().any(|p| &p.peer_id == pid));
    for p in &mut state.peers {
        p.unread_count = state.unread_by_peer.get(&p.peer_id).copied().unwrap_or(0);
    }

    unsafe {
        SendMessageW(handles.main_peer_list, LB_RESETCONTENT, 0, 0);
        let broadcast_text = if state.broadcast_unread_count > 0 {
            format!("全体チャット（全員） ({})", state.broadcast_unread_count)
        } else {
            "全体チャット（全員）".to_string()
        };
        let broadcast_label = to_wide(&broadcast_text);
        SendMessageW(
            handles.main_peer_list,
            LB_ADDSTRING,
            0,
            broadcast_label.as_ptr() as LPARAM,
        );
        let mut sel_idx: usize = 0;
        for (i, peer) in state.peers.iter().enumerate() {
            let label_w = to_wide(&peer.format_list_label());
            SendMessageW(
                handles.main_peer_list,
                LB_ADDSTRING,
                0,
                label_w.as_ptr() as LPARAM,
            );
            if state.active_thread == ThreadKey::Peer(peer.peer_id.clone()) {
                sel_idx = i + 1;
            }
        }
        SendMessageW(handles.main_peer_list, LB_SETCURSEL, sel_idx, 0);
    }

    update_thread_header(handles, state);
    update_status_bar(handles, state);
    thread_changed
}

pub(crate) struct LvSyncArgs {
    pub hwnd_lv: HWND,
    pub prev_count: usize,
    pub new_count: usize,
    pub allow_autoscroll: bool,
}

pub(crate) fn prepare_virtual_listview_sync(
    handles: &UiHandles,
    state: &mut UiState,
    allow_autoscroll: bool,
) -> LvSyncArgs {
    let prev_count = state.last_lv_count;
    let new_count = state.log_reader.thread_len(&state.active_thread);
    state.last_lv_count = new_count;
    LvSyncArgs {
        hwnd_lv: handles.main_chat_list,
        prev_count,
        new_count,
        allow_autoscroll,
    }
}

pub(crate) fn should_autoscroll_to_tail(
    prev_count: usize,
    new_count: usize,
    prev_sel: Option<usize>,
    allow_autoscroll: bool,
) -> bool {
    if !allow_autoscroll || new_count == 0 {
        return false;
    }
    let at_tail = prev_count > 0 && prev_sel == Some(prev_count - 1);
    prev_sel.is_none() || at_tail || prev_sel >= Some(new_count)
}

/// RefCell 借用解放後に呼び出し、同期 LVN_GETDISPINFOW 再入によるスキップを防止する。
pub(crate) fn apply_virtual_listview_sync(args: LvSyncArgs) {
    if args.hwnd_lv.is_null() {
        return;
    }
    let prev_sel = get_selected_listview_index(args.hwnd_lv);
    unsafe {
        SendMessageW(
            args.hwnd_lv,
            LVM_SETITEMCOUNT,
            args.new_count,
            LVSICF_NOSCROLL as isize,
        );
        if args.new_count > 0 {
            SendMessageW(
                args.hwnd_lv,
                LVM_REDRAWITEMS,
                0,
                (args.new_count - 1) as isize,
            );
            if should_autoscroll_to_tail(
                args.prev_count,
                args.new_count,
                prev_sel,
                args.allow_autoscroll,
            ) {
                SendMessageW(args.hwnd_lv, LVM_ENSUREVISIBLE, args.new_count - 1, 0);
            }
        }
    }
}

pub(crate) struct ClearMainControlsArgs {
    pub peer_list: HWND,
    pub thread_header: HWND,
    pub notice: HWND,
    pub chat_list: HWND,
    pub reply_label: HWND,
    pub reply_clear_btn: HWND,
    pub input_edit: HWND,
    pub statusbar: HWND,
}

pub(crate) fn extract_clear_main_args(
    handles: &UiHandles,
    state: &mut UiState,
) -> ClearMainControlsArgs {
    state.last_lv_count = 0;
    state.notice_text.clear();
    ClearMainControlsArgs {
        peer_list: handles.main_peer_list,
        thread_header: handles.main_thread_header,
        notice: handles.main_notice,
        chat_list: handles.main_chat_list,
        reply_label: handles.main_reply_label,
        reply_clear_btn: handles.main_reply_clear_btn,
        input_edit: handles.main_input_edit,
        statusbar: handles.main_statusbar,
    }
}

/// ログアウト／終了時に UI 借用外でメイン画面の全表示テキストを消去する。
pub(crate) fn apply_clear_main_controls(args: ClearMainControlsArgs) {
    let empty = to_wide("");
    let default_header = to_wide("全体チャット（全員）");
    let sb_parts = ["未ログイン", "CODE: ------", "オンライン: 0人", "NIC未接続"];
    unsafe {
        SendMessageW(args.chat_list, LVM_SETITEMCOUNT, 0, 0);
        SendMessageW(args.peer_list, LB_RESETCONTENT, 0, 0);
        SetWindowTextW(args.thread_header, default_header.as_ptr());
        SetWindowTextW(args.notice, empty.as_ptr());
        SetWindowTextW(args.reply_label, empty.as_ptr());
        ShowWindow(args.reply_label, SW_HIDE);
        ShowWindow(args.reply_clear_btn, SW_HIDE);
        SetWindowTextW(args.input_edit, empty.as_ptr());
        for (idx, part) in sb_parts.iter().enumerate() {
            let w = to_wide(part);
            SendMessageW(args.statusbar, SB_SETTEXTW, idx, w.as_ptr() as LPARAM);
        }
    }
}

pub(crate) fn handle_lv_getdispinfo(lparam: LPARAM, state: &UiState) {
    if lparam == 0 {
        return;
    }
    let di = unsafe { &mut *(lparam as *mut NMLVDISPINFOW) };
    if (di.item.mask & LVIF_TEXT) == 0 || di.item.iItem < 0 {
        return;
    }
    let row = di.item.iItem as usize;
    let col = di.item.iSubItem;
    let hwnd_lv = di.hdr.hwndFrom;
    match state
        .log_reader
        .try_with_message(&state.active_thread, row, |m| {
            Zeroizing::new(match col {
                0 => m.sender_name.clone(),
                1 => {
                    let mention_prefix = if !m.is_deleted
                        && matches!(m.delivery, DeliveryState::Received)
                        && contains_mention(&m.body, &state.display_name)
                    {
                        "[自分宛] "
                    } else {
                        ""
                    };
                    if !m.is_deleted
                        && let Some(reply) = &m.reply_to
                    {
                        format!(
                            "{mention_prefix}[返信: {}] {}",
                            reply.sender_name,
                            summarize_message_body(&m.body, 55)
                        )
                    } else {
                        format!("{mention_prefix}{}", summarize_message_body(&m.body, 70))
                    }
                }
                2 => format_unix_time_hms(m.timestamp),
                3 => m.delivery.status_label(),
                _ => String::new(),
            })
        }) {
        TryReadMessage::Hit(text) => write_utf16_buf(di.item.pszText, di.item.cchTextMax, &text),
        TryReadMessage::Empty => write_utf16_buf(di.item.pszText, di.item.cchTextMax, ""),
        TryReadMessage::Contended => {
            write_utf16_buf(di.item.pszText, di.item.cchTextMax, "");
            if !hwnd_lv.is_null() {
                unsafe {
                    let _ = InvalidateRect(hwnd_lv, null(), 0);
                }
            }
        }
    }
}

pub(crate) fn handle_peer_list_selchange() {
    let sync_args = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let sel = unsafe { SendMessageW(handles.main_peer_list, LB_GETCURSEL, 0, 0) };
        let next_thread = if sel > 0 {
            state
                .peers
                .get((sel as usize) - 1)
                .map_or(ThreadKey::Broadcast, |p| ThreadKey::Peer(p.peer_id.clone()))
        } else {
            ThreadKey::Broadcast
        };
        let cleared = clear_unread_for_thread(state, &next_thread);
        if next_thread != state.active_thread {
            state.active_thread = next_thread;
            state.last_lv_count = 0;
            state.pending_reply = None;
            let parent = unsafe { GetParent(handles.main_input_edit) };
            sync_reply_bar(parent, handles, state);
            refresh_peer_list(handles, state);
            sync_file_transfer_button(handles, state);
            Some(prepare_virtual_listview_sync(handles, state, true))
        } else if cleared {
            refresh_peer_list(handles, state);
            sync_file_transfer_button(handles, state);
            None
        } else {
            sync_file_transfer_button(handles, state);
            None
        }
    })
    .flatten();

    if let Some(args) = sync_args {
        apply_virtual_listview_sync(args);
    }
}

pub(crate) fn jump_to_search_hit(thread: ThreadKey, index: usize) {
    let post = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        clear_unread_for_thread(state, &thread);
        if state.active_thread != thread {
            state.active_thread = thread;
            state.last_lv_count = 0;
        }
        refresh_peer_list(handles, state);
        sync_file_transfer_button(handles, state);
        let lv = prepare_virtual_listview_sync(handles, state, false);
        Some((lv, handles.main_chat_list))
    })
    .flatten();

    if let Some((lv, hwnd_lv)) = post {
        apply_virtual_listview_sync(lv);
        focus_control(hwnd_lv);
        focus_listview_item(hwnd_lv, index);
    }
}

pub(crate) fn send_current_input() {
    let raw = with_ui(|handles| read_window_text_zeroizing(handles.main_input_edit));
    let Some(raw_text) = raw else {
        return;
    };
    let normalized = match validate_chat_body(&raw_text) {
        Ok(b) => Zeroizing::new(b),
        Err(err) => {
            let focus_target = with_ui_and_state_mut(|handles, state| {
                set_notice_text(handles, state, &err.to_string());
                handles.main_input_edit
            });
            if let Some(target) = focus_target {
                focus_control(target);
            }
            return;
        }
    };

    let focus_target = with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let thread = state.active_thread.clone();
        let reply_to = state.pending_reply.clone();
        if state
            .cmd_tx
            .try_send(UiCommand::SendChat {
                thread,
                body: normalized,
                reply_to,
            })
            .is_err()
        {
            set_notice_text(
                handles,
                state,
                "送信キューが混雑しています。少し待ってから再度お試しください。",
            );
            return Some(handles.main_input_edit);
        }
        if state.pending_reply.take().is_some() {
            let parent = unsafe { GetParent(handles.main_input_edit) };
            sync_reply_bar(parent, handles, state);
        }
        let empty = to_wide("");
        unsafe {
            SetWindowTextW(handles.main_input_edit, empty.as_ptr());
        }
        set_notice_text(handles, state, "");
        Some(handles.main_input_edit)
    })
    .flatten();
    if let Some(target) = focus_target {
        focus_control(target);
    }
}

enum DetailLookup {
    Ignore,
    Ready {
        row: usize,
        msg_id: String,
        detail: DetailDialogInput,
        thread: ThreadKey,
        dpi: u32,
        hwnd_lv: HWND,
    },
}

pub(crate) fn open_selected_message_detail(hwnd_parent: HWND) {
    let lookup = with_ui_and_state_mut(|handles, state| {
        if state.modal_open || state.app_state != AppStateKind::LoggedIn {
            return DetailLookup::Ignore;
        }
        let Some(row) = get_selected_listview_index(handles.main_chat_list) else {
            set_notice_text(
                handles,
                state,
                "全文を表示するメッセージを会話一覧から選択してください。",
            );
            return DetailLookup::Ignore;
        };
        let Some((msg_id, detail)) =
            state
                .log_reader
                .with_message(&state.active_thread, row, |m| {
                    (
                        m.message_id.clone(),
                        DetailDialogInput {
                            sender_name: m.sender_name.clone(),
                            time_text: format_unix_datetime(m.timestamp),
                            status_text: m.delivery.status_label(),
                            body: m.body.clone(),
                            can_retry: is_message_retryable(&m.delivery, m.is_deleted),
                            reply_summary: m
                                .reply_to
                                .as_ref()
                                .map(|r| format!("{}「{}」", r.sender_name, r.preview)),
                        },
                    )
                })
        else {
            return DetailLookup::Ignore;
        };
        state.modal_open = true;
        DetailLookup::Ready {
            row,
            msg_id,
            detail,
            thread: state.active_thread.clone(),
            dpi: state.dpi,
            hwnd_lv: handles.main_chat_list,
        }
    })
    .unwrap_or(DetailLookup::Ignore);

    let DetailLookup::Ready {
        row,
        msg_id,
        detail,
        thread,
        dpi,
        hwnd_lv,
    } = lookup
    else {
        return;
    };

    let action = show_message_detail_dialog(hwnd_parent, &detail, dpi);
    drop(detail);

    let target_row = with_ui_and_state_mut(|handles, state| {
        state.modal_open = false;
        if action == DetailDialogAction::Retry && state.app_state == AppStateKind::LoggedIn {
            let _ = state.cmd_tx.try_send(UiCommand::RetryChat {
                thread,
                message_id: msg_id,
            });
            set_notice_text(handles, state, "未達メッセージの再送を試行しています...");
        }
        let current_len = state.log_reader.thread_len(&state.active_thread);
        (current_len > 0).then(|| row.min(current_len - 1))
    })
    .flatten();

    if let Some(target_idx) = target_row {
        focus_listview_item(hwnd_lv, target_idx);
    } else {
        focus_control(hwnd_lv);
    }
    process_pending_file_offers(hwnd_parent);
}

pub(crate) fn retry_selected_message() {
    with_ui_and_state_mut(|handles, state| {
        if state.app_state != AppStateKind::LoggedIn {
            return;
        }
        let Some(row) = get_selected_listview_index(handles.main_chat_list) else {
            set_notice_text(
                handles,
                state,
                "再送対象のメッセージを会話一覧から選択してください。",
            );
            return;
        };
        let found = state
            .log_reader
            .with_message(&state.active_thread, row, |m| {
                is_message_retryable(&m.delivery, m.is_deleted).then(|| m.message_id.clone())
            });
        if let Some(Some(message_id)) = found {
            let _ = state.cmd_tx.try_send(UiCommand::RetryChat {
                thread: state.active_thread.clone(),
                message_id,
            });
            set_notice_text(handles, state, "未達メッセージの再送を試行しています...");
        } else {
            set_notice_text(
                handles,
                state,
                "選択されたメッセージは再送対象ではありません。",
            );
        }
    });
}

pub(crate) fn export_current_chat_log(hwnd_parent: HWND) {
    let snapshot = with_ui_and_state_mut(|handles, state| {
        if state.modal_open || state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let messages = state
            .log_reader
            .export_thread_messages(&state.active_thread);
        if messages.is_empty() {
            set_notice_text(handles, state, "保存対象の会話メッセージがありません。");
            return None;
        }
        let thread_label = match &state.active_thread {
            ThreadKey::Broadcast => "全体チャット".to_string(),
            ThreadKey::Peer(pid) => state
                .peers
                .iter()
                .find(|p| &p.peer_id == pid)
                .map_or_else(|| "1対1チャット".to_string(), |p| p.display_name.clone()),
        };
        state.modal_open = true;
        Some((thread_label, messages))
    })
    .flatten();

    let Some((thread_label, mut messages)) = snapshot else {
        return;
    };

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let default_name = default_chat_log_filename(&thread_label, now_secs);
    let picked = pick_save_text_log_dialog(hwnd_parent, &default_name);

    let notice_msg = if let Some(path) = picked {
        let exported_at = format_unix_datetime(now_secs);
        let text = format_chat_log_export_text(&thread_label, &exported_at, &messages);
        let write_res = std::fs::write(&path, text.as_bytes());
        drop(text);
        Some(match write_res {
            Ok(()) => format!("会話ログを保存しました: {}", path.display()),
            Err(err) => format!("会話ログの保存に失敗しました: {err}"),
        })
    } else {
        None
    };

    for msg in &mut messages {
        msg.zeroize();
    }
    drop(messages);

    let focus_target = with_ui_and_state_mut(|handles, state| {
        state.modal_open = false;
        if let Some(msg) = notice_msg {
            set_notice_text(handles, state, &msg);
        }
        if !state.last_focus.is_null() {
            state.last_focus
        } else {
            handles.main_input_edit
        }
    });

    if let Some(target) = focus_target {
        focus_control(target);
    }
    process_pending_file_offers(hwnd_parent);
}

pub(crate) fn show_chat_list_context_menu(hwnd_parent: HWND, lparam: LPARAM) {
    const CMD_SHOW_DETAIL: i32 = 1;
    const CMD_COPY_BODY: i32 = 2;
    const CMD_RETRY_MESSAGE: i32 = 3;
    const CMD_DELETE_MESSAGE: i32 = 4;
    const CMD_REPLY_MESSAGE: i32 = 5;
    const CMD_MENTION_SENDER: i32 = 6;

    let ctx = with_ui_and_state_mut(|handles, state| {
        if state.modal_open || state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let row = get_selected_listview_index(handles.main_chat_list)?;
        let (msg_id, sender_name, body, is_deleted, can_retry, can_delete) = state
            .log_reader
            .with_message(&state.active_thread, row, |m| {
                (
                    m.message_id.clone(),
                    m.sender_name.clone(),
                    Zeroizing::new(m.body.clone()),
                    m.is_deleted,
                    is_message_retryable(&m.delivery, m.is_deleted),
                    !m.is_deleted && !matches!(m.delivery, DeliveryState::Received),
                )
            })?;
        Some((
            row,
            msg_id,
            sender_name,
            body,
            is_deleted,
            can_retry,
            can_delete,
            state.active_thread.clone(),
            state.dpi,
            handles.main_chat_list,
        ))
    })
    .flatten();

    let Some((
        row,
        msg_id,
        sender_name,
        body,
        is_deleted,
        can_retry,
        can_delete,
        thread,
        dpi,
        hwnd_lv,
    )) = ctx
    else {
        return;
    };

    let mut x = (lparam & 0xFFFF) as i16 as i32;
    let mut y = ((lparam >> 16) & 0xFFFF) as i16 as i32;
    if x == -1 && y == -1 {
        let mut rc: RECT = unsafe { std::mem::zeroed() };
        rc.left = LVIR_BOUNDS as i32;
        let ok = unsafe { SendMessageW(hwnd_lv, LVM_GETITEMRECT, row, &raw mut rc as LPARAM) };
        if ok != 0 {
            let mut pt = POINT {
                x: rc.left + 24,
                y: rc.bottom,
            };
            unsafe {
                ClientToScreen(hwnd_lv, &raw mut pt);
            }
            x = pt.x;
            y = pt.y;
        } else {
            let mut wr: RECT = unsafe { std::mem::zeroed() };
            unsafe {
                GetWindowRect(hwnd_lv, &raw mut wr);
            }
            x = wr.left + 24;
            y = wr.top + 24;
        }
    }

    let cmd = unsafe {
        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }
        let w_detail = to_wide("メッセージの詳細を表示(&V)");
        let w_reply = to_wide("このメッセージに返信(&R)");
        let w_mention = to_wide(&format!("@{sender_name} でメンション(&M)"));
        let w_copy = to_wide("本文をコピー(&C)");
        let w_retry = to_wide("未達メッセージを再送(&T)");
        let w_delete = to_wide("メッセージを削除(&D)");

        AppendMenuW(
            hmenu,
            MF_STRING,
            CMD_SHOW_DETAIL as usize,
            w_detail.as_ptr(),
        );
        AppendMenuW(
            hmenu,
            MF_STRING | if !is_deleted { 0 } else { MF_GRAYED },
            CMD_REPLY_MESSAGE as usize,
            w_reply.as_ptr(),
        );
        AppendMenuW(
            hmenu,
            MF_STRING,
            CMD_MENTION_SENDER as usize,
            w_mention.as_ptr(),
        );
        AppendMenuW(hmenu, MF_STRING, CMD_COPY_BODY as usize, w_copy.as_ptr());
        AppendMenuW(
            hmenu,
            MF_STRING | if can_retry { 0 } else { MF_GRAYED },
            CMD_RETRY_MESSAGE as usize,
            w_retry.as_ptr(),
        );
        AppendMenuW(hmenu, MF_SEPARATOR, 0, null());
        AppendMenuW(
            hmenu,
            MF_STRING | if can_delete { 0 } else { MF_GRAYED },
            CMD_DELETE_MESSAGE as usize,
            w_delete.as_ptr(),
        );

        let selected = TrackPopupMenu(
            hmenu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
            x,
            y,
            0,
            hwnd_parent,
            null(),
        );
        DestroyMenu(hmenu);
        selected
    };

    match cmd {
        CMD_SHOW_DETAIL => open_selected_message_detail(hwnd_parent),
        CMD_REPLY_MESSAGE if !is_deleted => {
            let focus_target = with_ui_and_state_mut(|handles, state| {
                if state.app_state != AppStateKind::LoggedIn {
                    return None;
                }
                state.pending_reply = Some(ReplyReference {
                    message_id: msg_id,
                    sender_name,
                    preview: sanitize_reply_preview(&body),
                });
                sync_reply_bar(hwnd_parent, handles, state);
                Some(handles.main_input_edit)
            })
            .flatten();
            if let Some(target) = focus_target {
                focus_control(target);
            }
        }
        CMD_MENTION_SENDER => {
            let focus_target = with_ui_and_state(|handles, state| {
                if state.app_state != AppStateKind::LoggedIn {
                    return None;
                }
                insert_mention_into_input(handles.main_input_edit, &sender_name);
                Some(handles.main_input_edit)
            })
            .flatten();
            if let Some(target) = focus_target {
                focus_control(target);
            }
        }
        CMD_COPY_BODY => {
            let ok = copy_text_to_clipboard(hwnd_parent, &body);
            with_ui_and_state_mut(|handles, state| {
                if ok {
                    set_notice_text(
                        handles,
                        state,
                        "メッセージ本文をクリップボードにコピーしました。",
                    );
                } else {
                    set_notice_text(handles, state, "クリップボードへのコピーに失敗しました。");
                }
            });
        }
        CMD_RETRY_MESSAGE => retry_selected_message(),
        CMD_DELETE_MESSAGE if can_delete => {
            let entered = with_state_mut(|state| {
                if state.modal_open || state.app_state != AppStateKind::LoggedIn {
                    return false;
                }
                state.modal_open = true;
                true
            })
            .unwrap_or(false);
            if !entered {
                return;
            }
            let confirmed = confirm_delete_message(hwnd_parent, dpi);
            with_ui_and_state_mut(|handles, state| {
                state.modal_open = false;
                if confirmed && state.app_state == AppStateKind::LoggedIn {
                    let _ = state.cmd_tx.try_send(UiCommand::DeleteMessage {
                        thread,
                        message_id: msg_id,
                    });
                    set_notice_text(handles, state, "メッセージを削除しました。");
                }
            });
            focus_control(hwnd_lv);
            process_pending_file_offers(hwnd_parent);
        }
        _ => {}
    }
}

fn insert_mention_into_input(hwnd_input: HWND, display_name: &str) {
    if hwnd_input.is_null() || display_name.trim().is_empty() {
        return;
    }
    let mention = format!("@{} ", display_name.trim());
    let w = to_wide(&mention);
    unsafe {
        SendMessageW(hwnd_input, EM_REPLACESEL, 1, w.as_ptr() as LPARAM);
    }
}

pub(crate) fn show_mention_picker_menu(hwnd_parent: HWND) {
    let ctx = with_ui_and_state_mut(|handles, state| {
        if state.modal_open || state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let online: Vec<String> = state
            .peers
            .iter()
            .filter(|p| p.is_online)
            .map(|p| p.display_name.clone())
            .collect();
        if online.is_empty() {
            set_notice_text(handles, state, "現在オンラインの相手がいません。");
            return None;
        }
        Some((online, handles.main_input_edit))
    })
    .flatten();

    let Some((online, hwnd_input)) = ctx else {
        return;
    };

    let mut wr: RECT = unsafe { std::mem::zeroed() };
    unsafe {
        GetWindowRect(hwnd_input, &raw mut wr);
    }

    let selected_idx = unsafe {
        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }
        for (i, name) in online.iter().enumerate() {
            let label = to_wide(&format!("@{name}"));
            AppendMenuW(hmenu, MF_STRING, i + 1, label.as_ptr());
        }
        let cmd = TrackPopupMenu(
            hmenu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
            wr.left + 8,
            wr.top + 8,
            0,
            hwnd_parent,
            null(),
        );
        DestroyMenu(hmenu);
        cmd
    };

    if selected_idx > 0
        && let Some(name) = online.get((selected_idx as usize) - 1)
    {
        insert_mention_into_input(hwnd_input, name);
        focus_control(hwnd_input);
    }
}

pub(crate) fn show_peer_list_context_menu(hwnd_parent: HWND, lparam: LPARAM) {
    let ctx = with_ui_and_state(|handles, state| {
        if state.modal_open || state.app_state != AppStateKind::LoggedIn {
            return None;
        }
        let sel = unsafe { SendMessageW(handles.main_peer_list, LB_GETCURSEL, 0, 0) };
        if sel <= 0 {
            return None;
        }
        let peer = state.peers.get((sel as usize) - 1)?;
        Some((
            peer.display_name.clone(),
            handles.main_peer_list,
            handles.main_input_edit,
        ))
    })
    .flatten();

    let Some((display_name, hwnd_peer_list, hwnd_input)) = ctx else {
        return;
    };

    let mut x = (lparam & 0xFFFF) as i16 as i32;
    let mut y = ((lparam >> 16) & 0xFFFF) as i16 as i32;
    if x == -1 && y == -1 {
        let mut wr: RECT = unsafe { std::mem::zeroed() };
        unsafe {
            GetWindowRect(hwnd_peer_list, &raw mut wr);
        }
        x = wr.left + 24;
        y = wr.top + 24;
    }

    let cmd = unsafe {
        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }
        let w_mention = to_wide(&format!("@{display_name} でメンション(&M)"));
        AppendMenuW(hmenu, MF_STRING, 1, w_mention.as_ptr());
        let selected = TrackPopupMenu(
            hmenu,
            TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RETURNCMD,
            x,
            y,
            0,
            hwnd_parent,
            null(),
        );
        DestroyMenu(hmenu);
        selected
    };

    if cmd == 1 {
        insert_mention_into_input(hwnd_input, &display_name);
        focus_control(hwnd_input);
    }
}

#[cfg(test)]
mod tests {
    use super::should_autoscroll_to_tail;

    #[test]
    fn autoscroll_follows_tail_on_append_and_memory_eviction() {
        assert!(should_autoscroll_to_tail(0, 5, None, true));
        assert!(should_autoscroll_to_tail(10, 11, None, true));
        assert!(should_autoscroll_to_tail(10, 11, Some(9), true));
        // メモリ上限退避により件数が維持・減少した場合でも末尾追従する
        assert!(should_autoscroll_to_tail(50, 50, Some(49), true));
        assert!(should_autoscroll_to_tail(50, 48, Some(49), true));
        assert!(should_autoscroll_to_tail(50, 48, None, true));
        // 過去メッセージ閲覧中は追従しない
        assert!(!should_autoscroll_to_tail(50, 51, Some(10), true));
        assert!(!should_autoscroll_to_tail(50, 48, Some(10), true));
        // 自動スクロール不許可・空スレッドは追従しない
        assert!(!should_autoscroll_to_tail(10, 11, None, false));
        assert!(!should_autoscroll_to_tail(5, 0, Some(4), true));
    }
}
