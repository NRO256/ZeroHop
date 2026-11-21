use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock, Weak};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::CryptoError;
use crate::domain::validation::validate_password;
use crate::storage::cache_wipe::wipe_cache_dir_best_effort;

pub const ARGON2_SALT: &[u8] = b"LanMessenger-v4-Argon2id-Salt";
pub const ARGON2_M_COST_KIB: u32 = 65_536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

const CONTEXT_MSG_KEY: &str = "LMSG-v4-msg-key";
const CONTEXT_BEACON_KEY: &str = "LMSG-v4-beacon-key";
const CONTEXT_ROOM_CODE: &str = "LMSG-v4-room-code";
const CONTEXT_LOCK_VERIFY: &str = "LMSG-v4-lock-verify";

/// I / O / 0 / 1 を除外した 32文字 Crockford Base32 アルファベット
const ROOM_CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const ROOM_CODE_LEN: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    pub const fn production() -> Self {
        Self {
            m_cost_kib: ARGON2_M_COST_KIB,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::production()
    }
}

#[repr(C)]
#[derive(Zeroize)]
struct RawKeyMaterial {
    msg_key: [u8; 32],
    beacon_key: [u8; 32],
    lock_verifier: [u8; 32],
    temp_disk_key: [u8; 32],
}

#[cfg(windows)]
fn try_virtual_lock(ptr: *const core::ffi::c_void, size: usize) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    unsafe { VirtualLock(ptr, size) != 0 }
}

#[cfg(not(windows))]
fn try_virtual_lock(_ptr: *const core::ffi::c_void, _size: usize) -> bool {
    false
}

#[cfg(windows)]
fn try_virtual_unlock(ptr: *const core::ffi::c_void, size: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    unsafe {
        let _ = VirtualUnlock(ptr, size);
    }
}

#[cfg(not(windows))]
fn try_virtual_unlock(_ptr: *const core::ffi::c_void, _size: usize) {}

struct LockedKeyMaterial {
    raw: Box<RawKeyMaterial>,
    room_code: String,
    virtual_locked: bool,
    zeroized: bool,
}

impl LockedKeyMaterial {
    fn new(raw: RawKeyMaterial, room_code: String) -> Self {
        let boxed = Box::new(raw);
        let ptr: *const RawKeyMaterial = &*boxed;
        let virtual_locked = try_virtual_lock(
            ptr.cast::<core::ffi::c_void>(),
            std::mem::size_of::<RawKeyMaterial>(),
        );
        Self {
            raw: boxed,
            room_code,
            virtual_locked,
            zeroized: false,
        }
    }

    fn zeroize_and_unlock(&mut self) {
        self.raw.zeroize();
        self.room_code.zeroize();
        self.zeroized = true;
        if self.virtual_locked {
            let ptr: *const RawKeyMaterial = &*self.raw;
            try_virtual_unlock(
                ptr.cast::<core::ffi::c_void>(),
                std::mem::size_of::<RawKeyMaterial>(),
            );
            self.virtual_locked = false;
        }
    }
}

impl Drop for LockedKeyMaterial {
    fn drop(&mut self) {
        self.zeroize_and_unlock();
    }
}

type KeyRegistryList = Vec<Weak<Mutex<LockedKeyMaterial>>>;

static ACTIVE_KEY_REGISTRY: OnceLock<Mutex<KeyRegistryList>> = OnceLock::new();
static PANIC_HOOK_ONCE: Once = Once::new();
static PANIC_CACHE_DIR: OnceLock<Mutex<PathBuf>> = OnceLock::new();

fn key_registry() -> &'static Mutex<KeyRegistryList> {
    ACTIVE_KEY_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn register_key_material(handle: &Arc<Mutex<LockedKeyMaterial>>) {
    let mut reg = key_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.retain(|weak| weak.strong_count() > 0);
    reg.push(Arc::downgrade(handle));
}

fn prune_registry_dead_entries() {
    if let Ok(mut reg) = key_registry().try_lock() {
        reg.retain(|weak| weak.strong_count() > 0);
    }
}

pub fn emergency_zeroize_all_registered_keys() -> usize {
    let Ok(mut reg) = key_registry().try_lock() else {
        return 0;
    };
    let mut wiped = 0usize;
    for weak in reg.iter() {
        if let Some(arc) = weak.upgrade()
            && let Ok(mut guard) = arc.try_lock()
            && !guard.zeroized
        {
            guard.zeroize_and_unlock();
            wiped += 1;
        }
    }
    reg.retain(|weak| weak.strong_count() > 0);
    wiped
}

pub fn install_emergency_panic_hook(cache_dir: PathBuf) {
    let dir_cell = PANIC_CACHE_DIR.get_or_init(|| Mutex::new(cache_dir.clone()));
    if let Ok(mut guard) = dir_cell.lock() {
        *guard = cache_dir;
    }

    PANIC_HOOK_ONCE.call_once(|| {
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = emergency_zeroize_all_registered_keys();
            if let Some(cell) = PANIC_CACHE_DIR.get()
                && let Ok(guard) = cell.try_lock()
            {
                wipe_cache_dir_best_effort(&guard);
            }
            prev_hook(info);
        }));
    });
}

/// 導出されたセッション鍵（メモリ限定・VirtualLock 対象・Drop 時自動ゼロクリア）
pub struct SessionKeys {
    inner: Arc<Mutex<LockedKeyMaterial>>,
    params: Argon2Params,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("room_code", &"[REDACTED]")
            .field("virtual_locked", &self.is_virtual_locked())
            .finish()
    }
}

impl SessionKeys {
    pub fn with_msg_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, CryptoError> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.zeroized {
            return Err(CryptoError::KeyZeroized);
        }
        Ok(f(&guard.raw.msg_key))
    }

    pub fn with_beacon_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, CryptoError> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.zeroized {
            return Err(CryptoError::KeyZeroized);
        }
        Ok(f(&guard.raw.beacon_key))
    }

    pub fn with_temp_disk_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, CryptoError> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.zeroized {
            return Err(CryptoError::KeyZeroized);
        }
        Ok(f(&guard.raw.temp_disk_key))
    }

    pub fn room_code(&self) -> String {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.zeroized {
            String::new()
        } else {
            guard.room_code.clone()
        }
    }

    pub fn is_virtual_locked(&self) -> bool {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.virtual_locked
    }

    pub fn is_zeroized(&self) -> bool {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.zeroized
    }

    pub fn verify_lock_verifier(&self, candidate: &[u8; 32]) -> bool {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.zeroized {
            return false;
        }
        bool::from(guard.raw.lock_verifier.ct_eq(candidate))
    }

    pub fn verify_lock_password(&self, password: &str) -> Result<bool, CryptoError> {
        let candidate = derive_lock_verifier(password, self.params)?;
        Ok(self.verify_lock_verifier(&candidate))
    }

    pub fn zeroize_now(&self) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.zeroize_and_unlock();
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(
        &self,
    ) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], String, bool) {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            guard.raw.msg_key,
            guard.raw.beacon_key,
            guard.raw.lock_verifier,
            guard.raw.temp_disk_key,
            guard.room_code.clone(),
            guard.virtual_locked,
        )
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.zeroize_now();
        prune_registry_dead_entries();
    }
}

fn derive_master_secret(
    password: &str,
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    validate_password(password)?;
    let argon2_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut master_secret = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), ARGON2_SALT, &mut *master_secret)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    Ok(master_secret)
}

fn encode_room_code(raw: &[u8; 32]) -> String {
    let mut code = String::with_capacity(ROOM_CODE_LEN);
    for &byte in raw.iter().take(ROOM_CODE_LEN) {
        let idx = (byte & 0x1F) as usize;
        code.push(ROOM_CODE_ALPHABET[idx] as char);
    }
    code
}

pub fn derive_session_keys(password: &str) -> Result<SessionKeys, CryptoError> {
    derive_session_keys_with_params(password, Argon2Params::production())
}

pub fn derive_session_keys_with_params(
    password: &str,
    params: Argon2Params,
) -> Result<SessionKeys, CryptoError> {
    let mut master_secret = derive_master_secret(password, params)?;

    let msg_key = blake3::derive_key(CONTEXT_MSG_KEY, &*master_secret);
    let beacon_key = blake3::derive_key(CONTEXT_BEACON_KEY, &*master_secret);
    let lock_verifier = blake3::derive_key(CONTEXT_LOCK_VERIFY, &*master_secret);
    let mut room_raw = Zeroizing::new(blake3::derive_key(CONTEXT_ROOM_CODE, &*master_secret));
    let room_code = encode_room_code(&room_raw);
    room_raw.zeroize();

    // ステップ2完了直後に master_secret を即時 zeroize 破棄
    master_secret.zeroize();

    let mut temp_disk_key = [0u8; 32];
    OsRng.fill_bytes(&mut temp_disk_key);

    let material = RawKeyMaterial {
        msg_key,
        beacon_key,
        lock_verifier,
        temp_disk_key,
    };
    let locked = Arc::new(Mutex::new(LockedKeyMaterial::new(material, room_code)));
    register_key_material(&locked);

    Ok(SessionKeys {
        inner: locked,
        params,
    })
}

pub fn derive_lock_verifier(
    password: &str,
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut master_secret = derive_master_secret(password, params)?;
    let verifier = Zeroizing::new(blake3::derive_key(CONTEXT_LOCK_VERIFY, &*master_secret));
    master_secret.zeroize();
    Ok(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    static KDF_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn production_argon2id_derivation_is_deterministic_and_separates_four_keys() {
        let _guard = KDF_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys_a = derive_session_keys("CorrectHorse#2026").unwrap();
        let keys_b = derive_session_keys("CorrectHorse#2026").unwrap();
        let keys_other = derive_session_keys("DifferentPass#2026").unwrap();

        let (msg_a, beacon_a, lock_a, temp_a, code_a, _) = keys_a.snapshot_for_test();
        let (msg_b, beacon_b, lock_b, temp_b, code_b, _) = keys_b.snapshot_for_test();
        let (msg_o, _, _, _, code_o, _) = keys_other.snapshot_for_test();

        // パスワード依存 3鍵 + room_code は再現性一致
        assert_eq!(msg_a, msg_b);
        assert_eq!(beacon_a, beacon_b);
        assert_eq!(lock_a, lock_b);
        assert_eq!(code_a, code_b);

        // temp_disk_key は揮発ランダム生成のため毎回異なる
        assert_ne!(temp_a, temp_b);
        assert_ne!(temp_a, [0u8; 32]);

        // 4系統鍵は互いに独立
        assert_ne!(msg_a, beacon_a);
        assert_ne!(msg_a, lock_a);
        assert_ne!(beacon_a, lock_a);
        assert_ne!(msg_a, temp_a);

        // 別パスワードは異なる鍵・確認コード
        assert_ne!(msg_a, msg_o);
        assert_ne!(code_a, code_o);

        // room_code は 6文字 Crockford Base32（I/O/0/1 除外）
        assert_eq!(code_a.len(), 6);
        assert!(
            code_a
                .bytes()
                .all(|b| ROOM_CODE_ALPHABET.contains(&b) && !matches!(b, b'I' | b'O' | b'0' | b'1'))
        );

        // Debug 出力に鍵や room_code が出ないこと
        let debug_str = format!("{keys_a:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&code_a));
    }

    #[test]
    fn short_password_is_rejected_by_kdf() {
        let err = derive_session_keys("1234567").unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPassword(_)));
    }

    #[test]
    fn constant_time_lock_verifier_and_zeroize_behavior() {
        let _guard = KDF_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let params = Argon2Params {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let keys = derive_session_keys_with_params("UnlockSecret!99", params).unwrap();
        assert!(keys.verify_lock_password("UnlockSecret!99").unwrap());
        assert!(!keys.verify_lock_password("WrongSecret!99").unwrap());

        keys.zeroize_now();
        assert!(keys.is_zeroized());
        assert!(!keys.verify_lock_password("UnlockSecret!99").unwrap());
        assert!(matches!(
            keys.with_msg_key(|k| *k),
            Err(CryptoError::KeyZeroized)
        ));

        let (msg, beacon, lock, temp, code, vlocked) = keys.snapshot_for_test();
        assert_eq!(msg, [0u8; 32]);
        assert_eq!(beacon, [0u8; 32]);
        assert_eq!(lock, [0u8; 32]);
        assert_eq!(temp, [0u8; 32]);
        assert!(code.is_empty());
        assert!(!vlocked);
    }

    #[test]
    fn emergency_zeroize_clears_active_registered_keys() {
        let _guard = KDF_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let params = Argon2Params {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let keys = derive_session_keys_with_params("PanicSafeKey#1", params).unwrap();
        assert!(!keys.is_zeroized());

        let wiped = emergency_zeroize_all_registered_keys();
        assert!(wiped >= 1);
        assert!(keys.is_zeroized());

        let (msg, beacon, lock, temp, code, vlocked) = keys.snapshot_for_test();
        assert_eq!(msg, [0u8; 32]);
        assert_eq!(beacon, [0u8; 32]);
        assert_eq!(lock, [0u8; 32]);
        assert_eq!(temp, [0u8; 32]);
        assert!(code.is_empty());
        assert!(!vlocked);
    }
}
