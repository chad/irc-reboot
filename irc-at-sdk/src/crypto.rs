//! Cryptographic operations for AT Protocol identity verification.
//!
//! Supports:
//! - secp256k1 (MUST per spec)
//! - ed25519 (SHOULD per spec)
//!
//! Key formats: multibase (z = base58btc) + multicodec prefix

use anyhow::{Context, Result, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Multicodec varint prefixes for public key types.
const MULTICODEC_SECP256K1_PUB: [u8; 2] = [0xe7, 0x01];
const MULTICODEC_ED25519_PUB: [u8; 2] = [0xed, 0x01];

/// A parsed public key from a DID document.
#[derive(Debug, Clone)]
pub enum PublicKey {
    Secp256k1(k256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// A private key for signing challenges.
#[derive(Debug)]
pub enum PrivateKey {
    Secp256k1(k256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl PublicKey {
    /// Parse a `publicKeyMultibase` value from a DID document.
    ///
    /// Expected format: "z" + base58btc(multicodec_prefix + key_bytes)
    pub fn from_multibase(multibase: &str) -> Result<Self> {
        let Some(encoded) = multibase.strip_prefix('z') else {
            bail!("Unsupported multibase prefix (expected 'z' for base58btc)");
        };

        let bytes = bs58::decode(encoded)
            .into_vec()
            .context("Invalid base58btc encoding")?;

        if bytes.len() < 2 {
            bail!("Multicodec key too short");
        }

        if bytes.starts_with(&MULTICODEC_SECP256K1_PUB) {
            let key_bytes = &bytes[2..];
            let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                .context("Invalid secp256k1 public key")?;
            Ok(PublicKey::Secp256k1(verifying_key))
        } else if bytes.starts_with(&MULTICODEC_ED25519_PUB) {
            let key_bytes = &bytes[2..];
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .context("ed25519 public key must be 32 bytes")?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
                .context("Invalid ed25519 public key")?;
            Ok(PublicKey::Ed25519(verifying_key))
        } else {
            bail!(
                "Unsupported multicodec key type: 0x{:02x} 0x{:02x}",
                bytes[0],
                bytes[1]
            );
        }
    }

    /// Verify a signature over the given message bytes.
    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        match self {
            PublicKey::Secp256k1(key) => {
                use k256::ecdsa::signature::Verifier;
                let sig = k256::ecdsa::Signature::from_slice(signature_bytes)
                    .context("Invalid secp256k1 signature format")?;
                key.verify(message, &sig)
                    .context("secp256k1 signature verification failed")?;
            }
            PublicKey::Ed25519(key) => {
                use ed25519_dalek::Verifier;
                let sig = ed25519_dalek::Signature::from_slice(signature_bytes)
                    .context("Invalid ed25519 signature format")?;
                key.verify(message, &sig)
                    .context("ed25519 signature verification failed")?;
            }
        }
        Ok(())
    }

    /// Key type name for logging.
    pub fn key_type(&self) -> &'static str {
        match self {
            PublicKey::Secp256k1(_) => "secp256k1",
            PublicKey::Ed25519(_) => "ed25519",
        }
    }
}

impl PrivateKey {
    /// Generate a new secp256k1 keypair.
    pub fn generate_secp256k1() -> Self {
        let signing_key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        PrivateKey::Secp256k1(signing_key)
    }

    /// Generate a new ed25519 keypair.
    pub fn generate_ed25519() -> Self {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        PrivateKey::Ed25519(signing_key)
    }

    /// Load a secp256k1 private key from raw bytes (32 bytes).
    pub fn secp256k1_from_bytes(bytes: &[u8]) -> Result<Self> {
        let key = k256::ecdsa::SigningKey::from_slice(bytes)
            .context("Invalid secp256k1 private key")?;
        Ok(PrivateKey::Secp256k1(key))
    }

    /// Load an ed25519 private key from raw bytes (32 bytes).
    pub fn ed25519_from_bytes(bytes: &[u8]) -> Result<Self> {
        let key_array: [u8; 32] = bytes
            .try_into()
            .context("ed25519 private key must be 32 bytes")?;
        Ok(PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
            &key_array,
        )))
    }

    /// Sign a message and return the raw signature bytes.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Secp256k1(key) => {
                use k256::ecdsa::signature::Signer;
                let sig: k256::ecdsa::Signature = key.sign(message);
                sig.to_bytes().to_vec()
            }
            PrivateKey::Ed25519(key) => {
                use ed25519_dalek::Signer;
                let sig = key.sign(message);
                sig.to_bytes().to_vec()
            }
        }
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Secp256k1(key) => {
                PublicKey::Secp256k1(*key.verifying_key())
            }
            PrivateKey::Ed25519(key) => {
                PublicKey::Ed25519(key.verifying_key())
            }
        }
    }

    /// Encode the public key as a multibase string for DID documents.
    pub fn public_key_multibase(&self) -> String {
        let mut bytes = Vec::new();
        match self {
            PrivateKey::Secp256k1(key) => {
                bytes.extend_from_slice(&MULTICODEC_SECP256K1_PUB);
                let vk = key.verifying_key();
                bytes.extend_from_slice(&vk.to_sec1_bytes());
            }
            PrivateKey::Ed25519(key) => {
                bytes.extend_from_slice(&MULTICODEC_ED25519_PUB);
                bytes.extend_from_slice(key.verifying_key().as_bytes());
            }
        }
        format!("z{}", bs58::encode(&bytes).into_string())
    }

    /// Sign a message and return base64url-encoded signature.
    pub fn sign_base64url(&self, message: &[u8]) -> String {
        let sig_bytes = self.sign(message);
        URL_SAFE_NO_PAD.encode(&sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let private_key = PrivateKey::generate_secp256k1();
        let public_key = private_key.public_key();
        let message = b"test challenge data";
        let sig = private_key.sign(message);
        public_key.verify(message, &sig).unwrap();
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let private_key = PrivateKey::generate_ed25519();
        let public_key = private_key.public_key();
        let message = b"test challenge data";
        let sig = private_key.sign(message);
        public_key.verify(message, &sig).unwrap();
    }

    #[test]
    fn secp256k1_multibase_roundtrip() {
        let private_key = PrivateKey::generate_secp256k1();
        let multibase = private_key.public_key_multibase();
        assert!(multibase.starts_with('z'));
        let parsed = PublicKey::from_multibase(&multibase).unwrap();
        assert_eq!(parsed.key_type(), "secp256k1");

        // Verify that parsed key can verify signatures
        let message = b"roundtrip test";
        let sig = private_key.sign(message);
        parsed.verify(message, &sig).unwrap();
    }

    #[test]
    fn ed25519_multibase_roundtrip() {
        let private_key = PrivateKey::generate_ed25519();
        let multibase = private_key.public_key_multibase();
        let parsed = PublicKey::from_multibase(&multibase).unwrap();
        assert_eq!(parsed.key_type(), "ed25519");

        let message = b"roundtrip test";
        let sig = private_key.sign(message);
        parsed.verify(message, &sig).unwrap();
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key1 = PrivateKey::generate_secp256k1();
        let key2 = PrivateKey::generate_secp256k1();
        let message = b"test";
        let sig = key1.sign(message);
        assert!(key2.public_key().verify(message, &sig).is_err());
    }

    #[test]
    fn wrong_message_fails_verification() {
        let key = PrivateKey::generate_secp256k1();
        let sig = key.sign(b"message A");
        assert!(key.public_key().verify(b"message B", &sig).is_err());
    }
}
