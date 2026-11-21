//! メイン画面（接続先リスト・仮想 ListView 会話一覧・入力欄・4区画ステータスバー・AppEvent 調停）。

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{HFONT, InvalidateRect};
use windows_sys::Win32::System::SystemServices::{SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::{
    EM_SETLIMITTEXT, EM_SETSEL, LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCFMT_LEFT,
    LVCOLUMNW, LVIF_TEXT, LVM_ENSUREVISIBLE, LVM_INSERTCOLUMNW, LVM_REDRAWITEMS,
    LVM_SETCOLUMNWIDTH, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMCOUNT, LVS_EX_DOUBLEBUFFER,
    LVS_EX_FULLROWSELECT, LVS_OWNERDATA, LVS_REPORT, LVS_SHOWSELALWAYS, LVS_SINGLESEL,
    LVSICF_NOSCROLL, NMLVDISPINFOW, SB_SETPARTS, SB_SETTEXTW, STATUSCLASSNAMEW, WC_LISTVIEWW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CONTROL, VK_RETURN};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_PUSHBUTTON, CreateWindowExW, DLGC_WANTMESSAGE, DestroyWindow, ES_AUTOHSCROLL,
    ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, ES_WANTRETURN, LB_ADDSTRING, LB_GETCURSEL,
    LB_RESETCONTENT, LB_SETCURSEL, LBS_NOINTEGRALHEIGHT, LBS_NOTIFY, MSG, MoveWindow, PostMessageW,
    SW_HIDE, SW_SHOW, SendMessageW, SetMenu, SetWindowTextW, ShowWindow, WM_CHAR, WM_GETDLGCODE,
    WM_IME_ENDCOMPOSITION, WM_IME_STARTCOMPOSITION, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_SETFONT,
    WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VSCROLL,
};
use zeroize::Zeroizing;

use lan_messenger::app::state::{AppEvent, AppStateKind, UiCommand};
use lan_messenger::domain::model::{MAX_MESSAGES_PER_THREAD, ThreadKey};
use lan_messenger::domain::validation::validate_chat_body;

use super::a11y::{
    focus_control, focus_listview_item, get_selected_listview_index, set_cue_banner,
};
use super::dialogs::{DetailDialogAction, DetailDialogInput, show_message_detail_dialog};
use super::login_view::{
    reset_login_form, set_authenticating_ui, set_login_status_message, show_login_controls,
};
use super::menu_bar::{sync_menu_enabled_state, sync_status_menu_check};
use super::state_helpers::{UiHandles, UiState, with_state, with_ui, with_ui_and_state_mut};
use super::theme::{apply_listview_explorer_theme, scale_dpi};
use super::{
    IDC_MAIN_BYTE_GUIDE, IDC_MAIN_CHAT_LIST, IDC_MAIN_INPUT_EDIT, IDC_MAIN_NOTICE,
    IDC_MAIN_PEER_LABEL, IDC_MAIN_PEER_LIST, IDC_MAIN_SEND_BTN, IDC_MAIN_STATUSBAR,
    IDC_MAIN_THREAD_HEADER, WM_APP_OPEN_DETAIL, format_bytes_human, format_remaining_bytes_label,
    format_unix_datetime, format_unix_time_hms, is_message_retryable, normalized_utf8_byte_len,
    read_window_text_zeroizing, resolve_migrated_thread, summarize_message_body, to_wide,
    write_utf16_buf,
};

const SUBCLASS_ID_CHAT_LIST: usize = 201;
const SUBCLASS_ID_INPUT_EDIT: usize = 202;

pub(crate) struct MainControlHandles {
    pub peer_label: HWND,
    pub peer_list: HWND,
    pub thread_header: HWND,
    pub notice: HWND,
    pub chat_list: HWND,
    pub byte_guide: HWND,
    pub input_edit: HWND,
    pub send_btn: HWND,
    pub statusbar: HWND,
}

#[allow(clippy::too_many_arguments)]
fn make_ctrl(
    parent: HWND,
    hinst: windows_sys::Win32::Foundation::HANDLE,
    class_w: *const u16,
    text: &str,
    ex_style: u32,
    style: u32,
    id: usize,
    font: HFONT,
) -> HWND {
    let txt_w = to_wide(text);
    unsafe {
        let hwnd = CreateWindowExW(
            ex_style,
            class_w,
            txt_w.as_ptr(),
            style,
            0,
            0,
            100,
            24,
            parent,
            id as _,
            hinst,
            null_mut(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
        hwnd
    }
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
        static IME_COMPOSING: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        static SUPPRESS_NEXT_LF: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);

        match msg {
            WM_IME_STARTCOMPOSITION => {
                IME_COMPOSING.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            WM_IME_ENDCOMPOSITION => {
                IME_COMPOSING.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            WM_KILLFOCUS => {
                IME_COMPOSING.store(false, std::sync::atomic::Ordering::Relaxed);
                SUPPRESS_NEXT_LF.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            WM_KEYDOWN => {
                let ctrl_down = (GetKeyState(i32::from(VK_CONTROL)) as u16 & 0x8000) != 0;
                if ctrl_down && wparam == usize::from(VK_RETURN) {
                    SUPPRESS_NEXT_LF.store(true, std::sync::atomic::Ordering::Relaxed);
                    if !IME_COMPOSING.load(std::sync::atomic::Ordering::Relaxed) {
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
                if ctrl_down && wparam == b'A' as usize {
                    SendMessageW(hwnd, EM_SETSEL, 0, -1);
                    return 0;
                }
            }
            WM_KEYUP if wparam == usize::from(VK_RETURN) => {
                SUPPRESS_NEXT_LF.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            WM_CHAR => {
                if wparam == 0x0A
                    && SUPPRESS_NEXT_LF.swap(false, std::sync::atomic::Ordering::Relaxed)
                {
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

    let peer_label = make_ctrl(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "接続先(&P):",
        0,
        static_style,
        IDC_MAIN_PEER_LABEL,
        ui_font,
    );
    let peer_list = make_ctrl(
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
    let thread_header = make_ctrl(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        "全体チャット（全員）",
        0,
        static_style,
        IDC_MAIN_THREAD_HEADER,
        bold_font,
    );
    let notice = make_ctrl(
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
        insert_column(hwnd, 1, "時刻", 76);
        insert_column(hwnd, 2, "メッセージ（Enterで全文）", 340);
        insert_column(hwnd, 3, "状態", 110);
        let _ = SetWindowSubclass(
            hwnd,
            Some(chat_list_subclass_proc),
            SUBCLASS_ID_CHAT_LIST,
            hwnd_parent as usize,
        );
        hwnd
    };
    let initial_byte_guide = format_remaining_bytes_label(0);
    let byte_guide = make_ctrl(
        hwnd_parent,
        hinst,
        static_w.as_ptr(),
        &initial_byte_guide,
        0,
        static_style,
        IDC_MAIN_BYTE_GUIDE,
        ui_font,
    );
    let input_edit = make_ctrl(
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
    set_cue_banner(input_edit, "メッセージを入力（Ctrl+Enter で送信）");

    let send_btn = make_ctrl(
        hwnd_parent,
        hinst,
        button_w.as_ptr(),
        "送信(&S)",
        0,
        WS_CHILD | WS_TABSTOP | (BS_PUSHBUTTON as u32),
        IDC_MAIN_SEND_BTN,
        ui_font,
    );
    let statusbar = make_ctrl(
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
        byte_guide,
        input_edit,
        send_btn,
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
        let guide_h = s(20);
        let btn_w = s(96);
        let list_h = (client_h - sb_h - pad - y - guide_h - input_h - s(10)).max(s(100));

        MoveWindow(handles.main_chat_list, right_x, y, right_w, list_h, 1);
        y += list_h + s(6);

        MoveWindow(handles.main_byte_guide, right_x, y, right_w, guide_h, 1);
        y += guide_h + s(4);

        let edit_w = (right_w - btn_w - s(8)).max(s(120));
        MoveWindow(handles.main_input_edit, right_x, y, edit_w, input_h, 1);
        MoveWindow(
            handles.main_send_btn,
            right_x + edit_w + s(8),
            y,
            btn_w,
            input_h,
            1,
        );

        // 仮想 ListView 列幅の自動配分
        let col0 = s(108);
        let col1 = s(76);
        let col3 = s(112);
        let col2 = (right_w - col0 - col1 - col3 - s(24)).max(s(140));
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

pub(crate) fn update_input_byte_guide(handles: &UiHandles) {
    let text = read_window_text_zeroizing(handles.main_input_edit);
    let utf8_bytes = normalized_utf8_byte_len(&text);
    let label = format_remaining_bytes_label(utf8_bytes);
    let w = to_wide(&label);
    unsafe {
        SetWindowTextW(handles.main_byte_guide, w.as_ptr());
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
        "オンライン: {}人 / ログ: {}",
        online_peers + usize::from(state.app_state == AppStateKind::LoggedIn),
        format_bytes_human(state.total_log_bytes)
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

pub(crate) fn refresh_peer_list(handles: &UiHandles, state: &mut UiState) -> bool {
    let migrated = resolve_migrated_thread(&state.active_thread, &state.peers);
    let thread_changed = migrated != state.active_thread;
    state.active_thread = migrated;

    unsafe {
        SendMessageW(handles.main_peer_list, LB_RESETCONTENT, 0, 0);
        let broadcast_label = to_wide("全体チャット（全員）");
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
            let at_tail = args.prev_count > 0 && prev_sel == Some(args.prev_count - 1);
            let appended = args.new_count > args.prev_count
                || (args.new_count >= MAX_MESSAGES_PER_THREAD
                    && args.prev_count >= MAX_MESSAGES_PER_THREAD);
            if args.allow_autoscroll && appended && (prev_sel.is_none() || at_tail) {
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
    pub byte_guide: HWND,
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
        byte_guide: handles.main_byte_guide,
        input_edit: handles.main_input_edit,
        statusbar: handles.main_statusbar,
    }
}

/// ログアウト／終了時に UI 借用外でメイン画面の全表示テキストを消去する。
pub(crate) fn apply_clear_main_controls(args: ClearMainControlsArgs) {
    let empty = to_wide("");
    let default_header = to_wide("全体チャット（全員）");
    let default_guide = to_wide(&format_remaining_bytes_label(0));
    let sb_parts = [
        "未ログイン",
        "CODE: ------",
        "オンライン: 0人 / ログ: 0 B",
        "NIC未接続",
    ];
    unsafe {
        SendMessageW(args.chat_list, LVM_SETITEMCOUNT, 0, 0);
        SendMessageW(args.peer_list, LB_RESETCONTENT, 0, 0);
        SetWindowTextW(args.thread_header, default_header.as_ptr());
        SetWindowTextW(args.notice, empty.as_ptr());
        SetWindowTextW(args.input_edit, empty.as_ptr());
        SetWindowTextW(args.byte_guide, default_guide.as_ptr());
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
    let text_opt = state
        .log_reader
        .with_message(&state.active_thread, row, |m| {
            Zeroizing::new(match col {
                0 => m.sender_name.clone(),
                1 => format_unix_time_hms(m.timestamp),
                2 => summarize_message_body(&m.body, 70),
                3 => m.delivery.status_label(),
                _ => String::new(),
            })
        });
    if let Some(text) = text_opt {
        write_utf16_buf(di.item.pszText, di.item.cchTextMax, &text);
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
        if next_thread != state.active_thread {
            state.active_thread = next_thread;
            state.last_lv_count = 0;
            update_thread_header(handles, state);
            Some(prepare_virtual_listview_sync(handles, state, true))
        } else {
            None
        }
    })
    .flatten();

    if let Some(args) = sync_args {
        apply_virtual_listview_sync(args);
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
        if state
            .cmd_tx
            .try_send(UiCommand::SendChat {
                thread,
                body: normalized,
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
        let empty = to_wide("");
        unsafe {
            SetWindowTextW(handles.main_input_edit, empty.as_ptr());
        }
        update_input_byte_guide(handles);
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
                            can_retry: is_message_retryable(&m.delivery),
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
                is_message_retryable(&m.delivery).then(|| m.message_id.clone())
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

pub(crate) fn drain_app_events(hwnd: HWND) {
    let events: Vec<AppEvent> =
        with_state(|state| state.event_rx.try_iter().collect()).unwrap_or_default();
    for ev in events {
        match ev {
            AppEvent::LoginSucceeded {
                display_name,
                room_code,
                ephemeral_peer_id,
                tcp_port,
                udp_port,
                nic_info,
            } => {
                let post = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::LoggedIn;
                    state.display_name = display_name;
                    state.room_code = room_code;
                    state.ephemeral_peer_id = ephemeral_peer_id;
                    state.tcp_port = tcp_port;
                    state.udp_port = udp_port;
                    state.nic_info = nic_info;
                    state.status = lan_messenger::domain::model::UserStatus::Online;
                    state.active_thread = ThreadKey::Broadcast;
                    state.peers.clear();
                    state.total_log_bytes = 0;
                    state.last_lv_count = 0;

                    set_authenticating_ui(handles, false);
                    reset_login_form(handles, false);
                    show_login_controls(handles, false);
                    unsafe {
                        SetMenu(hwnd, handles.hmenu_main);
                        windows_sys::Win32::UI::WindowsAndMessaging::DrawMenuBar(hwnd);
                    }
                    sync_menu_enabled_state(handles.hmenu_main, true);
                    sync_status_menu_check(handles.hmenu_status, state.status);
                    show_main_controls(handles, true);
                    refresh_peer_list(handles, state);
                    let lv = prepare_virtual_listview_sync(handles, state, true);
                    update_input_byte_guide(handles);
                    set_notice_text(handles, state, "");
                    state.last_focus = handles.main_input_edit;
                    (lv, handles.main_input_edit)
                });
                if let Some((lv, focus_target)) = post {
                    apply_virtual_listview_sync(lv);
                    focus_control(focus_target);
                }
            }
            AppEvent::LoginFailed { reason } => {
                let focus_target = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::LoggedOut;
                    set_authenticating_ui(handles, false);
                    set_login_status_message(handles, &reason);
                    handles.login_pass_edit
                });
                if let Some(target) = focus_target {
                    focus_control(target);
                }
            }
            AppEvent::PeerListChanged(new_peers) => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn || state.peers == new_peers {
                        return None;
                    }
                    state.peers = new_peers;
                    let thread_changed = refresh_peer_list(handles, state);
                    if thread_changed {
                        state.last_lv_count = 0;
                        Some(prepare_virtual_listview_sync(handles, state, true))
                    } else {
                        None
                    }
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::PeerJoined { .. } | AppEvent::PeerLeft { .. } => {}
            AppEvent::ThreadUpdated {
                thread,
                total_log_bytes,
                ..
            } => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return None;
                    }
                    state.total_log_bytes = total_log_bytes;
                    let actual_len = state.log_reader.thread_len(&state.active_thread);
                    let lv = if state.active_thread == thread || actual_len != state.last_lv_count {
                        Some(prepare_virtual_listview_sync(
                            handles,
                            state,
                            state.active_thread == thread,
                        ))
                    } else {
                        None
                    };
                    update_status_bar(handles, state);
                    lv
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::DeliveryUpdated { thread, .. } => {
                let lv_opt = with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return None;
                    }
                    state.total_log_bytes = state.log_reader.total_bytes();
                    let lv = if state.active_thread == thread {
                        Some(prepare_virtual_listview_sync(handles, state, false))
                    } else {
                        None
                    };
                    update_status_bar(handles, state);
                    lv
                })
                .flatten();
                if let Some(lv) = lv_opt {
                    apply_virtual_listview_sync(lv);
                }
            }
            AppEvent::NetworkRefreshed {
                nic_info,
                tcp_port,
                udp_port,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    state.nic_info = nic_info;
                    state.tcp_port = tcp_port;
                    state.udp_port = udp_port;
                    update_status_bar(handles, state);
                    set_notice_text(handles, state, "ネットワークアダプタ情報を更新しました。");
                });
            }
            AppEvent::StatusChanged(next_status) => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    state.status = next_status;
                    sync_status_menu_check(handles.hmenu_status, next_status);
                    update_status_bar(handles, state);
                });
            }
            AppEvent::KeyMismatchDetected { peer_ip } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【鍵不一致】{peer_ip} からの通信を復号できませんでした。ルームパスワードをご確認ください。"
                        ),
                    );
                });
            }
            AppEvent::ClockSkewDetected {
                peer_ip,
                skew_seconds,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【時刻ズレ】{peer_ip} との時刻差が許容範囲（±5分）を超えています（差: {skew_seconds}秒）。PCの時計同期をご確認ください。"
                        ),
                    );
                });
            }
            AppEvent::ProtocolVersionMismatch {
                peer_ip,
                received_version,
            } => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state != AppStateKind::LoggedIn {
                        return;
                    }
                    set_notice_text(
                        handles,
                        state,
                        &format!(
                            "【版数不一致】{peer_ip} から非互換プロトコル v{received_version} の通信を受信しました。"
                        ),
                    );
                });
            }
            AppEvent::ErrorNotice(msg) => {
                with_ui_and_state_mut(|handles, state| {
                    if state.app_state == AppStateKind::LoggedIn {
                        set_notice_text(handles, state, &msg);
                    } else {
                        set_login_status_message(handles, &msg);
                    }
                });
            }
            AppEvent::LogoutCompleted => {
                let post = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::LoggedOut;
                    let clear_args = extract_clear_main_args(handles, state);
                    state.clear_session_fields();
                    unsafe {
                        SetMenu(hwnd, null_mut());
                        windows_sys::Win32::UI::WindowsAndMessaging::DrawMenuBar(hwnd);
                    }
                    sync_menu_enabled_state(handles.hmenu_main, false);
                    show_main_controls(handles, false);
                    show_login_controls(handles, true);
                    set_authenticating_ui(handles, false);
                    reset_login_form(handles, false);
                    state.last_focus = handles.login_name_edit;
                    (clear_args, handles.login_name_edit)
                });
                if let Some((clear_args, focus_target)) = post {
                    apply_clear_main_controls(clear_args);
                    focus_control(focus_target);
                }
            }
            AppEvent::ShutdownReady => {
                let clear_args = with_ui_and_state_mut(|handles, state| {
                    state.app_state = AppStateKind::Exiting;
                    let args = extract_clear_main_args(handles, state);
                    state.clear_session_fields();
                    args
                });
                if let Some(args) = clear_args {
                    apply_clear_main_controls(args);
                }
                unsafe {
                    DestroyWindow(hwnd);
                }
            }
        }
    }
}
