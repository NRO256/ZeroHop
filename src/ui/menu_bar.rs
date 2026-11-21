//! 常設メニューバー生成と状態同期（Phase 1 範囲のみ）。

use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CheckMenuItem, CreateMenu, CreatePopupMenu, EnableMenuItem, HMENU, MF_BYCOMMAND,
    MF_CHECKED, MF_ENABLED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING, MF_UNCHECKED,
};

use lan_messenger::domain::model::UserStatus;

use super::{
    IDM_ABOUT, IDM_ADD_MANUAL_PEER, IDM_CLEAR_ALL, IDM_CLEAR_CURRENT, IDM_CONN_INFO, IDM_EXIT,
    IDM_LOGOUT, IDM_OPTIONS, IDM_REFRESH_NETWORK, IDM_RETRY_SELECTED, IDM_SHORTCUTS,
    IDM_SHOW_DETAIL, IDM_STATUS_AWAY, IDM_STATUS_BUSY, IDM_STATUS_ONLINE, to_wide,
};

pub(crate) struct MenuHandles {
    pub bar: HMENU,
    pub status_sub: HMENU,
}

fn append_str(menu: HMENU, id: usize, text: &str) {
    let w = to_wide(text);
    unsafe {
        AppendMenuW(menu, MF_STRING, id, w.as_ptr());
    }
}

fn append_sep(menu: HMENU) {
    unsafe {
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    }
}

fn append_popup(parent: HMENU, sub: HMENU, text: &str) {
    let w = to_wide(text);
    unsafe {
        AppendMenuW(parent, MF_POPUP, sub as usize, w.as_ptr());
    }
}

pub(crate) fn create_main_menu_bar() -> MenuHandles {
    unsafe {
        let bar = CreateMenu();
        let account = CreatePopupMenu();
        let status_sub = CreatePopupMenu();
        let edit = CreatePopupMenu();
        let tools = CreatePopupMenu();
        let help = CreatePopupMenu();

        // アカウント(&A)
        append_str(status_sub, IDM_STATUS_ONLINE, "オンライン(&O)");
        append_str(status_sub, IDM_STATUS_AWAY, "離席中(&W)");
        append_str(status_sub, IDM_STATUS_BUSY, "取り込み中(&B)");
        append_popup(account, status_sub, "ステータス変更(&S)");
        append_sep(account);
        append_str(account, IDM_LOGOUT, "ログアウト(&L)\tCtrl+Shift+L");
        append_str(account, IDM_EXIT, "終了(&X)\tAlt+F4");
        append_popup(bar, account, "アカウント(&A)");

        // 編集・表示(&E)
        append_str(
            edit,
            IDM_SHOW_DETAIL,
            "選択メッセージの詳細を表示(&D)\tEnter",
        );
        append_str(edit, IDM_RETRY_SELECTED, "未達メッセージを再送(&R)");
        append_sep(edit);
        append_str(
            edit,
            IDM_CLEAR_CURRENT,
            "現在の会話表示をクリア(&C)\tCtrl+Shift+Del",
        );
        append_str(edit, IDM_CLEAR_ALL, "全会話メモリをクリア(&A)");
        append_popup(bar, edit, "編集・表示(&E)");

        // ツール(&T)
        append_str(tools, IDM_ADD_MANUAL_PEER, "手動ピア追加(&M)...\tCtrl+M");
        append_str(tools, IDM_REFRESH_NETWORK, "ネットワーク再検出(&R)\tF5");
        append_str(tools, IDM_CONN_INFO, "ルーム確認コード・通信情報(&I)...");
        append_str(tools, IDM_OPTIONS, "オプション設定(&O)...");
        append_popup(bar, tools, "ツール(&T)");

        // ヘルプ(&H)
        append_str(help, IDM_SHORTCUTS, "キーボードショートカット一覧(&K)");
        append_str(help, IDM_ABOUT, "バージョン情報(&A)");
        append_popup(bar, help, "ヘルプ(&H)");

        sync_status_menu_check(status_sub, UserStatus::Online);
        MenuHandles { bar, status_sub }
    }
}

pub(crate) fn sync_status_menu_check(hmenu_status: HMENU, status: UserStatus) {
    if hmenu_status.is_null() {
        return;
    }
    let items = [
        (IDM_STATUS_ONLINE, status == UserStatus::Online),
        (IDM_STATUS_AWAY, status == UserStatus::Away),
        (IDM_STATUS_BUSY, status == UserStatus::Busy),
    ];
    unsafe {
        for (id, checked) in items {
            let flag = MF_BYCOMMAND | if checked { MF_CHECKED } else { MF_UNCHECKED };
            CheckMenuItem(hmenu_status, id as u32, flag);
        }
    }
}

pub(crate) fn sync_menu_enabled_state(hmenu: HMENU, is_logged_in: bool) {
    if hmenu.is_null() {
        return;
    }
    let session_items = [
        IDM_STATUS_ONLINE,
        IDM_STATUS_AWAY,
        IDM_STATUS_BUSY,
        IDM_LOGOUT,
        IDM_SHOW_DETAIL,
        IDM_RETRY_SELECTED,
        IDM_CLEAR_CURRENT,
        IDM_CLEAR_ALL,
        IDM_ADD_MANUAL_PEER,
        IDM_REFRESH_NETWORK,
        IDM_CONN_INFO,
    ];
    let flag = MF_BYCOMMAND | if is_logged_in { MF_ENABLED } else { MF_GRAYED };
    unsafe {
        for id in session_items {
            EnableMenuItem(hmenu, id as u32, flag);
        }
    }
}
