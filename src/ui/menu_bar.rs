//! 常設メニューバー生成と状態同期（Phase 1 範囲のみ）。

use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CheckMenuItem, CreateMenu, CreatePopupMenu, EnableMenuItem, HMENU, MF_BYCOMMAND,
    MF_CHECKED, MF_ENABLED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING, MF_UNCHECKED,
};

use lan_messenger::app::state::AppStateKind;
use lan_messenger::domain::model::UserStatus;
use lan_messenger::storage::config::LocalConfig;

use super::{
    IDM_ABOUT, IDM_ADD_MANUAL_PEER, IDM_CANCEL_FILE_TRANSFER, IDM_CLEAR_ALL, IDM_CLEAR_CURRENT,
    IDM_CONN_INFO, IDM_EXIT, IDM_LOCK_SCREEN, IDM_LOGOUT, IDM_OPTIONS, IDM_REFRESH_NETWORK,
    IDM_RETRY_SELECTED, IDM_SEARCH, IDM_SEND_FILE, IDM_SHORTCUTS, IDM_SHOW_DETAIL, IDM_STATUS_AWAY,
    IDM_STATUS_BUSY, IDM_STATUS_ONLINE, IDM_TOGGLE_SEND_ON_ENTER, IDM_TOGGLE_SOUND, to_wide,
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
        append_str(account, IDM_LOCK_SCREEN, "画面ロック(&K)\tCtrl+L");
        append_sep(account);
        append_str(account, IDM_LOGOUT, "ログアウト(&L)\tCtrl+Shift+L");
        append_str(account, IDM_EXIT, "終了(&X)\tAlt+F4");
        append_popup(bar, account, "アカウント(&A)");

        // 編集・表示(&E)
        append_str(edit, IDM_SEARCH, "セッション内検索(&F)\tCtrl+F");
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
        append_sep(edit);
        append_str(edit, IDM_TOGGLE_SOUND, "効果音・通知音を有効にする(&S)");
        append_str(edit, IDM_TOGGLE_SEND_ON_ENTER, "Enterキーで送信する(&N)");
        append_popup(bar, edit, "編集・表示(&E)");

        // ツール(&T)
        append_str(tools, IDM_SEND_FILE, "ファイルを送信(&F)...\tCtrl+Shift+F");
        append_str(tools, IDM_CANCEL_FILE_TRANSFER, "ファイル転送を中止(&Z)");
        append_sep(tools);
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

pub(crate) fn sync_option_menu_checks(hmenu: HMENU, cfg: &LocalConfig) {
    if hmenu.is_null() {
        return;
    }
    unsafe {
        CheckMenuItem(
            hmenu,
            IDM_TOGGLE_SOUND as u32,
            MF_BYCOMMAND
                | if cfg.sound_enabled {
                    MF_CHECKED
                } else {
                    MF_UNCHECKED
                },
        );
        CheckMenuItem(
            hmenu,
            IDM_TOGGLE_SEND_ON_ENTER as u32,
            MF_BYCOMMAND
                | if cfg.send_on_enter {
                    MF_CHECKED
                } else {
                    MF_UNCHECKED
                },
        );
    }
}

pub(crate) fn sync_menu_enabled_state(hmenu: HMENU, app_state: AppStateKind) {
    if hmenu.is_null() {
        return;
    }
    let session_items = [
        IDM_STATUS_ONLINE,
        IDM_STATUS_AWAY,
        IDM_STATUS_BUSY,
        IDM_LOCK_SCREEN,
        IDM_SEARCH,
        IDM_SHOW_DETAIL,
        IDM_RETRY_SELECTED,
        IDM_CLEAR_CURRENT,
        IDM_CLEAR_ALL,
        IDM_ADD_MANUAL_PEER,
        IDM_REFRESH_NETWORK,
        IDM_CONN_INFO,
        IDM_SEND_FILE,
        IDM_CANCEL_FILE_TRANSFER,
    ];
    let is_logged_in = app_state == AppStateKind::LoggedIn;
    let can_logout = matches!(app_state, AppStateKind::LoggedIn | AppStateKind::Locked);
    let can_configure = app_state != AppStateKind::Locked
        && app_state != AppStateKind::Authenticating
        && app_state != AppStateKind::LoggingOut;

    unsafe {
        let session_flag = MF_BYCOMMAND | if is_logged_in { MF_ENABLED } else { MF_GRAYED };
        for id in session_items {
            EnableMenuItem(hmenu, id as u32, session_flag);
        }
        EnableMenuItem(
            hmenu,
            IDM_LOGOUT as u32,
            MF_BYCOMMAND | if can_logout { MF_ENABLED } else { MF_GRAYED },
        );
        for id in [IDM_OPTIONS, IDM_TOGGLE_SOUND, IDM_TOGGLE_SEND_ON_ENTER] {
            EnableMenuItem(
                hmenu,
                id as u32,
                MF_BYCOMMAND | if can_configure { MF_ENABLED } else { MF_GRAYED },
            );
        }
    }
}
