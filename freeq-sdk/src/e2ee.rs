//! End-to-end encryption for IRC channels.
//!
//! Uses AES-256-GCM with keys derived from a shared passphrase via
//! HKDF-SHA256. The server never sees plaintext — it just relays
//! ciphertext like any other PRIVMSG.
//!
//! # Wire format
//!
//! Encrypted messages are sent as normal PRIVMSG with the body:
//!
//! ```text
//! ENC1:<nonce-base64>:<ciphertext-base64>
//! ```
//!
//! - `ENC1` — version tag (future-proofs the format)
//! - `nonce` — 12-byte AES-GCM nonce, base64-encoded
//! - `ciphertext` — AES-256-GCM encrypted message + 16-byte auth tag, base64-encoded
//!
//! # Key derivation
//!
//! ```text
//! key = HKDF-SHA256(
//!   ikm: passphrase bytes,
//!   salt: SHA-256(channel name lowercase),
//!   info: b"freeq-e2ee-v1"
//! )
//! ```
//!
//! Using the channel name as salt means the same passphrase produces
//! different keys in different channels.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

/// Prefix that identifies an encrypted message on the wire.
pub const ENC_PREFIX: &str = "ENC1:";

/// Derive an AES-256 key from a passphrase and channel name.
pub fn derive_key(passphrase: &str, channel: &str) -> [u8; 32] {
    use sha2::Digest;
    let salt = Sha256::digest(channel.to_lowercase().as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), passphrase.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"freeq-e2ee-v1", &mut key)
        .expect("32 bytes is a valid length for HKDF-SHA256");
    key
}

/// Encrypt a plaintext message.
///
/// Returns the wire-format string: `ENC1:<nonce>:<ciphertext>`
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, EncryptError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptError::BadKey)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| EncryptError::EncryptFailed)?;

    let nonce_b64 = B64.encode(&nonce[..]);
    let ct_b64 = B64.encode(&ciphertext);

    Ok(format!("{ENC_PREFIX}{nonce_b64}:{ct_b64}"))
}

/// Decrypt a wire-format encrypted message.
///
/// Returns the plaintext string, or an error if the message isn't
/// encrypted, the key is wrong, or the ciphertext is tampered.
pub fn decrypt(key: &[u8; 32], wire: &str) -> Result<String, DecryptError> {
    let body = wire
        .strip_prefix(ENC_PREFIX)
        .ok_or(DecryptError::NotEncrypted)?;

    let (nonce_b64, ct_b64) = body
        .split_once(':')
        .ok_or(DecryptError::MalformedMessage)?;

    let nonce_bytes = B64.decode(nonce_b64).map_err(|_| DecryptError::MalformedMessage)?;
    let ct_bytes = B64.decode(ct_b64).map_err(|_| DecryptError::MalformedMessage)?;

    if nonce_bytes.len() != 12 {
        return Err(DecryptError::MalformedMessage);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DecryptError::BadKey)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| DecryptError::DecryptFailed)?;

    String::from_utf8(plaintext).map_err(|_| DecryptError::InvalidUtf8)
}

/// Check if a message body looks like an encrypted message.
pub fn is_encrypted(text: &str) -> bool {
    text.starts_with(ENC_PREFIX)
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptError {
    #[error("invalid key")]
    BadKey,
    #[error("encryption failed")]
    EncryptFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("not an encrypted message")]
    NotEncrypted,
    #[error("malformed encrypted message")]
    MalformedMessage,
    #[error("invalid key")]
    BadKey,
    #[error("decryption failed (wrong key or tampered)")]
    DecryptFailed,
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = derive_key("hunter2", "#secret-channel");
        let plaintext = "Hello, encrypted world!";
        let wire = encrypt(&key, plaintext).unwrap();

        assert!(wire.starts_with(ENC_PREFIX));
        assert!(is_encrypted(&wire));
        assert!(!is_encrypted("just a normal message"));

        let decrypted = decrypt(&key, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key("correct-password", "#channel");
        let key2 = derive_key("wrong-password", "#channel");
        let wire = encrypt(&key1, "secret stuff").unwrap();

        assert!(decrypt(&key2, &wire).is_err());
    }

    #[test]
    fn different_channels_different_keys() {
        let key1 = derive_key("same-password", "#channel-a");
        let key2 = derive_key("same-password", "#channel-b");
        assert_ne!(key1, key2);

        let wire = encrypt(&key1, "test").unwrap();
        assert!(decrypt(&key2, &wire).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key("password", "#test");
        let mut wire = encrypt(&key, "hello").unwrap();
        // Flip a character in the ciphertext
        let len = wire.len();
        unsafe { wire.as_bytes_mut()[len - 2] ^= 0xFF; }
        assert!(decrypt(&key, &wire).is_err());
    }

    #[test]
    fn not_encrypted_returns_error() {
        let key = derive_key("password", "#test");
        let result = decrypt(&key, "just a plain message");
        assert!(matches!(result, Err(DecryptError::NotEncrypted)));
    }

    #[test]
    fn empty_message() {
        let key = derive_key("password", "#test");
        let wire = encrypt(&key, "").unwrap();
        let decrypted = decrypt(&key, &wire).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn unicode_message() {
        let key = derive_key("パスワード", "#日本語");
        let plaintext = "こんにちは世界 🔐";
        let wire = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &wire).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
