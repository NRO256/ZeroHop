use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::crypto::CryptoError;

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

pub fn generate_nonce() -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt_aead(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce_ref,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn decrypt_aead(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_ref = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_rejection() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let other_key = [0x43u8; AEAD_KEY_LEN];
        let nonce = generate_nonce();
        let aad = b"ZHOP\x00\x04";
        let plaintext = b"Secret LAN message";

        let ct = encrypt_aead(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + AEAD_TAG_LEN);

        let pt = decrypt_aead(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(&*pt, plaintext);

        // AAD 改ざん拒否
        assert_eq!(
            decrypt_aead(&key, &nonce, b"ZHOP\x00\x03", &ct),
            Err(CryptoError::DecryptionFailed)
        );

        // 鍵違い拒否
        assert_eq!(
            decrypt_aead(&other_key, &nonce, aad, &ct),
            Err(CryptoError::DecryptionFailed)
        );

        // 暗号文改ざん拒否
        let mut tampered = ct.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            decrypt_aead(&key, &nonce, aad, &tampered),
            Err(CryptoError::DecryptionFailed)
        );
    }
}
