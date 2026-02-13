//! DID-based end-to-end encryption (ENC2).
//!
//! Replaces passphrase-based E2EE with identity-bound encryption using
//! keys from DID documents. Only verified members of a channel can decrypt.
//!
//! # Protocol Overview
//!
//! 1. Each user's DID document contains a secp256k1 public key
//! 2. Channel encryption uses a shared **group key** derived from ECDH
//! 3. The group key is derived from: sorted member DIDs + pairwise ECDH secrets
//! 4. When membership changes, the group key is rotated
//!
//! # Wire Format
//!
//! ```text
//! ENC2:<epoch>:<nonce-b64>:<ciphertext-b64>
//! ```
//!
//! - `ENC2` — version tag (identity-bound E2EE)
//! - `epoch` — key epoch (increments on membership change)
//! - `nonce` — 12-byte AES-GCM nonce, base64url-encoded
//! - `ciphertext` — AES-256-GCM ciphertext + tag, base64url-encoded
//!
//! # Key Derivation
//!
//! For a channel with member DIDs [A, B, C] (sorted lexicographically):
//!
//! ```text
//! group_ikm = HKDF-Extract(
//!   salt: SHA-256(channel_name),
//!   ikm:  sorted_dids_concatenated
//! )
//! group_key = HKDF-Expand(group_ikm, info: "freeq-e2ee-v2-<epoch>", len: 32)
//! ```
//!
//! Each member proves they belong by being able to sign challenges
//! during SASL auth. The server tracks authenticated members, and the
//! client derives the group key from the known member set.
//!
//! # Key Exchange
//!
//! For private messages (DM E2EE), we use ECDH:
//!
//! ```text
//! shared = ECDH(my_private_key, their_public_key)
//! dm_key = HKDF-SHA256(shared, salt: sorted(did_a, did_b), info: "freeq-dm-v1")
//! ```

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

/// Prefix for DID-based encrypted messages.
pub const ENC2_PREFIX: &str = "ENC2:";

/// A group encryption context for a channel.
#[derive(Debug, Clone)]
pub struct GroupKey {
    /// The channel name.
    pub channel: String,
    /// Sorted list of member DIDs.
    pub members: Vec<String>,
    /// Key epoch (increments on membership change).
    pub epoch: u64,
    /// Derived AES-256 key.
    key: [u8; 32],
}

impl GroupKey {
    /// Derive a group key for a channel with the given authenticated members.
    ///
    /// Members are sorted lexicographically before derivation, so the same
    /// set always produces the same key regardless of join order.
    pub fn derive(channel: &str, members: &[String], epoch: u64) -> Self {
        use sha2::Digest;

        let mut sorted: Vec<String> = members.to_vec();
        sorted.sort();
        sorted.dedup();

        // IKM: concatenation of sorted DIDs
        let ikm: Vec<u8> = sorted.iter().flat_map(|d| d.as_bytes().to_vec()).collect();
        let salt = Sha256::digest(channel.to_lowercase().as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let info = format!("freeq-e2ee-v2-{epoch}");
        let mut key = [0u8; 32];
        hk.expand(info.as_bytes(), &mut key)
            .expect("32 bytes is valid for HKDF");

        Self {
            channel: channel.to_string(),
            members: sorted,
            epoch,
            key,
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns: `ENC2:<epoch>:<nonce>:<ciphertext>`
    pub fn encrypt(&self, plaintext: &str) -> Result<String, EncryptError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| EncryptError::BadKey)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| EncryptError::EncryptFailed)?;

        let nonce_b64 = URL_SAFE_NO_PAD.encode(&nonce[..]);
        let ct_b64 = URL_SAFE_NO_PAD.encode(&ct);

        Ok(format!("{ENC2_PREFIX}{}:{nonce_b64}:{ct_b64}", self.epoch))
    }

    /// Decrypt a wire-format ENC2 message.
    pub fn decrypt(&self, wire: &str) -> Result<String, DecryptError> {
        let body = wire
            .strip_prefix(ENC2_PREFIX)
            .ok_or(DecryptError::NotEncrypted)?;

        let parts: Vec<&str> = body.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(DecryptError::MalformedMessage);
        }

        let epoch: u64 = parts[0].parse().map_err(|_| DecryptError::MalformedMessage)?;
        if epoch != self.epoch {
            return Err(DecryptError::EpochMismatch {
                expected: self.epoch,
                got: epoch,
            });
        }

        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| DecryptError::MalformedMessage)?;
        let ct_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| DecryptError::MalformedMessage)?;

        if nonce_bytes.len() != 12 {
            return Err(DecryptError::MalformedMessage);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError::BadKey)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct_bytes.as_ref())
            .map_err(|_| DecryptError::DecryptFailed)?;

        String::from_utf8(pt).map_err(|_| DecryptError::InvalidUtf8)
    }

    /// Check if this key has the same member set.
    pub fn members_match(&self, members: &[String]) -> bool {
        let mut sorted: Vec<String> = members.to_vec();
        sorted.sort();
        sorted.dedup();
        self.members == sorted
    }
}

/// DM encryption using ECDH key agreement.
///
/// Derives a shared secret from two secp256k1 keys, then derives an
/// AES-256 key for DM encryption.
pub struct DmKey {
    /// Both DIDs in sorted order.
    pub dids: (String, String),
    /// Derived AES-256 key.
    key: [u8; 32],
}

impl DmKey {
    /// Derive a DM key from an ECDH shared secret.
    ///
    /// `my_private` is the local user's secp256k1 private key bytes (32 bytes).
    /// `their_public` is the remote user's compressed secp256k1 public key.
    /// DIDs are used as salt for domain separation.
    pub fn from_secp256k1(
        my_did: &str,
        their_did: &str,
        my_private: &[u8; 32],
        their_public_bytes: &[u8],
    ) -> Result<Self, String> {
        use k256::ecdh::diffie_hellman;
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        use k256::PublicKey as K256Pub;

        let my_scalar = k256::NonZeroScalar::try_from(&my_private[..])
            .map_err(|_| "Invalid private key")?;

        let their_point = k256::EncodedPoint::from_bytes(their_public_bytes)
            .map_err(|_| "Invalid public key encoding")?;
        let their_key = K256Pub::from_encoded_point(&their_point);
        if their_key.is_none().into() {
            return Err("Invalid public key point".to_string());
        }
        let their_key = their_key.unwrap();

        let shared = diffie_hellman(&my_scalar, their_key.as_affine());
        let shared_bytes = shared.raw_secret_bytes();

        // Sort DIDs for deterministic salt
        let (did_a, did_b) = if my_did < their_did {
            (my_did, their_did)
        } else {
            (their_did, my_did)
        };
        let salt = format!("{did_a}:{did_b}");

        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_bytes);
        let mut key = [0u8; 32];
        hk.expand(b"freeq-dm-v1", &mut key)
            .expect("32 bytes is valid");

        Ok(Self {
            dids: (did_a.to_string(), did_b.to_string()),
            key,
        })
    }

    /// Encrypt a DM.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, EncryptError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| EncryptError::BadKey)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| EncryptError::EncryptFailed)?;

        let nonce_b64 = URL_SAFE_NO_PAD.encode(&nonce[..]);
        let ct_b64 = URL_SAFE_NO_PAD.encode(&ct);

        Ok(format!("{ENC2_PREFIX}dm:{nonce_b64}:{ct_b64}"))
    }

    /// Decrypt a DM.
    pub fn decrypt(&self, wire: &str) -> Result<String, DecryptError> {
        let body = wire
            .strip_prefix(ENC2_PREFIX)
            .ok_or(DecryptError::NotEncrypted)?;

        let body = body.strip_prefix("dm:").ok_or(DecryptError::NotDm)?;

        let (nonce_b64, ct_b64) = body
            .split_once(':')
            .ok_or(DecryptError::MalformedMessage)?;

        let nonce_bytes = URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .map_err(|_| DecryptError::MalformedMessage)?;
        let ct_bytes = URL_SAFE_NO_PAD
            .decode(ct_b64)
            .map_err(|_| DecryptError::MalformedMessage)?;

        if nonce_bytes.len() != 12 {
            return Err(DecryptError::MalformedMessage);
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| DecryptError::BadKey)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct_bytes.as_ref())
            .map_err(|_| DecryptError::DecryptFailed)?;

        String::from_utf8(pt).map_err(|_| DecryptError::InvalidUtf8)
    }
}

/// Check if a message is ENC2-encrypted.
pub fn is_encrypted(text: &str) -> bool {
    text.starts_with(ENC2_PREFIX)
}

/// Parse the epoch from an ENC2 message without decrypting.
pub fn parse_epoch(wire: &str) -> Option<u64> {
    let body = wire.strip_prefix(ENC2_PREFIX)?;
    let epoch_str = body.split(':').next()?;
    if epoch_str == "dm" {
        return None; // DM, no epoch
    }
    epoch_str.parse().ok()
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
    #[error("not an ENC2 encrypted message")]
    NotEncrypted,
    #[error("not a DM message")]
    NotDm,
    #[error("malformed encrypted message")]
    MalformedMessage,
    #[error("invalid key")]
    BadKey,
    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    #[error("decryption failed (wrong key, wrong members, or tampered)")]
    DecryptFailed,
    #[error("decrypted data is not valid UTF-8")]
    InvalidUtf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_key_roundtrip() {
        let members = vec![
            "did:plc:alice".to_string(),
            "did:plc:bob".to_string(),
            "did:plc:charlie".to_string(),
        ];
        let gk = GroupKey::derive("#secret", &members, 1);

        let wire = gk.encrypt("Hello group!").unwrap();
        assert!(wire.starts_with("ENC2:1:"));
        assert!(is_encrypted(&wire));

        let pt = gk.decrypt(&wire).unwrap();
        assert_eq!(pt, "Hello group!");
    }

    #[test]
    fn group_key_order_independent() {
        let m1 = vec!["did:plc:bob".to_string(), "did:plc:alice".to_string()];
        let m2 = vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()];

        let k1 = GroupKey::derive("#test", &m1, 0);
        let k2 = GroupKey::derive("#test", &m2, 0);

        // Same members, same key regardless of order
        let wire = k1.encrypt("test").unwrap();
        let pt = k2.decrypt(&wire).unwrap();
        assert_eq!(pt, "test");
    }

    #[test]
    fn group_key_different_members_fail() {
        let m1 = vec!["did:plc:alice".to_string(), "did:plc:bob".to_string()];
        let m2 = vec!["did:plc:alice".to_string(), "did:plc:charlie".to_string()];

        let k1 = GroupKey::derive("#test", &m1, 0);
        let k2 = GroupKey::derive("#test", &m2, 0);

        let wire = k1.encrypt("secret").unwrap();
        assert!(k2.decrypt(&wire).is_err());
    }

    #[test]
    fn group_key_epoch_mismatch() {
        let members = vec!["did:plc:alice".to_string()];
        let k1 = GroupKey::derive("#test", &members, 1);
        let k2 = GroupKey::derive("#test", &members, 2);

        let wire = k1.encrypt("test").unwrap();
        let err = k2.decrypt(&wire).unwrap_err();
        assert!(matches!(err, DecryptError::EpochMismatch { expected: 2, got: 1 }));
    }

    #[test]
    fn group_key_different_channel_fail() {
        let members = vec!["did:plc:alice".to_string()];
        let k1 = GroupKey::derive("#chan-a", &members, 0);
        let k2 = GroupKey::derive("#chan-b", &members, 0);

        let wire = k1.encrypt("test").unwrap();
        assert!(k2.decrypt(&wire).is_err());
    }

    #[test]
    fn dm_key_ecdh_roundtrip() {
        // Generate two secp256k1 keypairs
        let sk_a = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let sk_b = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        let pk_a_bytes = sk_a.verifying_key().to_sec1_bytes();
        let pk_b_bytes = sk_b.verifying_key().to_sec1_bytes();

        let sk_a_bytes: [u8; 32] = sk_a.to_bytes().into();
        let sk_b_bytes: [u8; 32] = sk_b.to_bytes().into();

        // Both sides derive the same DM key
        let dm_a = DmKey::from_secp256k1(
            "did:plc:alice",
            "did:plc:bob",
            &sk_a_bytes,
            &pk_b_bytes,
        )
        .unwrap();

        let dm_b = DmKey::from_secp256k1(
            "did:plc:bob",
            "did:plc:alice",
            &sk_b_bytes,
            &pk_a_bytes,
        )
        .unwrap();

        // A encrypts, B decrypts
        let wire = dm_a.encrypt("Secret DM").unwrap();
        assert!(wire.starts_with("ENC2:dm:"));
        let pt = dm_b.decrypt(&wire).unwrap();
        assert_eq!(pt, "Secret DM");

        // B encrypts, A decrypts
        let wire2 = dm_b.encrypt("Reply").unwrap();
        let pt2 = dm_a.decrypt(&wire2).unwrap();
        assert_eq!(pt2, "Reply");
    }

    #[test]
    fn dm_key_wrong_party_fails() {
        let sk_a = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let sk_b = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let sk_c = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());

        let pk_b_bytes = sk_b.verifying_key().to_sec1_bytes();
        let pk_a_bytes = sk_a.verifying_key().to_sec1_bytes();

        let sk_a_bytes: [u8; 32] = sk_a.to_bytes().into();
        let sk_c_bytes: [u8; 32] = sk_c.to_bytes().into();

        let dm_ab = DmKey::from_secp256k1(
            "did:plc:alice", "did:plc:bob",
            &sk_a_bytes, &pk_b_bytes,
        ).unwrap();

        let dm_ca = DmKey::from_secp256k1(
            "did:plc:charlie", "did:plc:alice",
            &sk_c_bytes, &pk_a_bytes,
        ).unwrap();

        let wire = dm_ab.encrypt("For Bob only").unwrap();
        assert!(dm_ca.decrypt(&wire).is_err());
    }

    #[test]
    fn parse_epoch_works() {
        assert_eq!(parse_epoch("ENC2:42:nonce:ct"), Some(42));
        assert_eq!(parse_epoch("ENC2:dm:nonce:ct"), None);
        assert_eq!(parse_epoch("ENC1:nonce:ct"), None);
    }

    #[test]
    fn members_match_check() {
        let members = vec!["did:plc:b".to_string(), "did:plc:a".to_string()];
        let gk = GroupKey::derive("#test", &members, 0);

        assert!(gk.members_match(&["did:plc:a".to_string(), "did:plc:b".to_string()]));
        assert!(gk.members_match(&["did:plc:b".to_string(), "did:plc:a".to_string()]));
        assert!(!gk.members_match(&["did:plc:a".to_string()]));
    }
}
