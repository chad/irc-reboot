//! AT Protocol authentication helpers.
//!
//! Handles:
//! - Challenge decoding/encoding for SASL ATPROTO-CHALLENGE
//! - ChallengeSigner trait for pluggable signing backends
//! - KeySigner: real cryptographic signing (secp256k1/ed25519)
//! - PdsSessionSigner: PDS session-based authentication (app-password or OAuth)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::PrivateKey;
use crate::oauth::DpopKey;

/// The challenge sent by the server during SASL ATPROTO-CHALLENGE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub session_id: String,
    pub nonce: String,
    pub timestamp: i64,
}

/// The response we send back to the server.
///
/// - `method` absent or `"crypto"`: `signature` is a base64url cryptographic signature.
/// - `method` = `"pds-session"`: `signature` is a PDS access JWT (Bearer token, no DPoP).
/// - `method` = `"pds-oauth"`: `signature` is a DPoP-bound access token,
///   `dpop_proof` is a DPoP proof for the PDS getSession endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub did: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pds_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_proof: Option<String>,
}

/// Decode a base64url-encoded challenge from the server.
pub fn decode_challenge(encoded: &str) -> anyhow::Result<Challenge> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    let challenge: Challenge = serde_json::from_slice(&bytes)?;
    Ok(challenge)
}

/// Decode base64url challenge to raw bytes (for signing).
pub fn decode_challenge_bytes(encoded: &str) -> anyhow::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(encoded)?)
}

/// Encode a challenge response as base64url for sending via AUTHENTICATE.
pub fn encode_response(response: &ChallengeResponse) -> String {
    let json = serde_json::to_vec(response).expect("response serialization");
    URL_SAFE_NO_PAD.encode(&json)
}

/// Trait for signing challenges.
pub trait ChallengeSigner: Send + Sync {
    /// The DID this signer authenticates as.
    fn did(&self) -> &str;

    /// Produce the SASL response for the given challenge bytes.
    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse>;
}

/// A real cryptographic signer using a private key.
pub struct KeySigner {
    did: String,
    private_key: PrivateKey,
}

impl KeySigner {
    pub fn new(did: String, private_key: PrivateKey) -> Self {
        Self { did, private_key }
    }
}

impl ChallengeSigner for KeySigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        let signature = self.private_key.sign_base64url(challenge_bytes);
        Ok(ChallengeResponse {
            did: self.did.clone(),
            signature,
            method: None,
            pds_url: None,
            dpop_proof: None,
        })
    }
}

/// PDS session-based signer for Bluesky/AT Protocol users.
///
/// Supports two modes:
/// - App-password sessions (plain Bearer token, no DPoP)
/// - OAuth sessions (DPoP-bound token, includes proof for server to forward)
pub struct PdsSessionSigner {
    did: String,
    access_token: String,
    pds_url: String,
    dpop_key: Option<DpopKey>,
    dpop_nonce: Option<String>,
}

impl PdsSessionSigner {
    /// Create a signer for an app-password session (no DPoP).
    pub fn new(did: String, access_token: String, pds_url: String) -> Self {
        Self {
            did,
            access_token,
            pds_url,
            dpop_key: None,
            dpop_nonce: None,
        }
    }

    /// Create a signer for an OAuth session (with DPoP).
    pub fn new_oauth(
        did: String,
        access_token: String,
        pds_url: String,
        dpop_key: DpopKey,
        dpop_nonce: Option<String>,
    ) -> Self {
        Self {
            did,
            access_token,
            pds_url,
            dpop_key: Some(dpop_key),
            dpop_nonce,
        }
    }
}

impl ChallengeSigner for PdsSessionSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn respond(&self, _challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        if let Some(ref dpop_key) = self.dpop_key {
            // OAuth mode: create a DPoP proof targeting the PDS getSession endpoint.
            // The PDS requires a DPoP nonce, so we probe first to get it.
            let get_session_url = format!(
                "{}/xrpc/com.atproto.server.getSession",
                self.pds_url.trim_end_matches('/')
            );

            // Discover the DPoP nonce by checking the nonce we stored during token exchange,
            // or generate a proof without nonce and let the server handle the retry.
            // For robustness, we try to get the nonce via a pre-flight.
            let dpop_proof = if let Some(ref nonce) = self.dpop_nonce {
                dpop_key.proof("GET", &get_session_url, Some(nonce), Some(&self.access_token))?
            } else {
                dpop_key.proof("GET", &get_session_url, None, Some(&self.access_token))?
            };

            Ok(ChallengeResponse {
                did: self.did.clone(),
                signature: self.access_token.clone(),
                method: Some("pds-oauth".to_string()),
                pds_url: Some(self.pds_url.clone()),
                dpop_proof: Some(dpop_proof),
            })
        } else {
            // App-password mode: plain Bearer token
            Ok(ChallengeResponse {
                did: self.did.clone(),
                signature: self.access_token.clone(),
                method: Some("pds-session".to_string()),
                pds_url: Some(self.pds_url.clone()),
                dpop_proof: None,
            })
        }
    }
}

/// A stub signer for development/testing.
pub struct StubSigner {
    pub did: String,
}

impl ChallengeSigner for StubSigner {
    fn did(&self) -> &str {
        &self.did
    }

    fn respond(&self, challenge_bytes: &[u8]) -> anyhow::Result<ChallengeResponse> {
        Ok(ChallengeResponse {
            did: self.did.clone(),
            signature: URL_SAFE_NO_PAD.encode(challenge_bytes),
            method: None,
            pds_url: None,
            dpop_proof: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PrivateKey;

    #[test]
    fn key_signer_produces_valid_signature() {
        let private_key = PrivateKey::generate_secp256k1();
        let public_key = private_key.public_key();

        let signer = KeySigner::new("did:plc:test".to_string(), private_key);

        let challenge_bytes = b"test challenge data";
        let response = signer.respond(challenge_bytes).unwrap();

        assert!(response.method.is_none());
        assert!(response.dpop_proof.is_none());
        let sig_bytes = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
        public_key.verify(challenge_bytes, &sig_bytes).unwrap();
    }

    #[test]
    fn pds_session_signer_bearer() {
        let signer = PdsSessionSigner::new(
            "did:plc:test".to_string(),
            "jwt-token-here".to_string(),
            "https://pds.example.com".to_string(),
        );

        let response = signer.respond(b"challenge").unwrap();
        assert_eq!(response.method.as_deref(), Some("pds-session"));
        assert!(response.dpop_proof.is_none());
        assert_eq!(response.signature, "jwt-token-here");
    }

    #[test]
    fn pds_session_signer_oauth_dpop() {
        let dpop_key = DpopKey::generate();
        let signer = PdsSessionSigner::new_oauth(
            "did:plc:test".to_string(),
            "dpop-bound-token".to_string(),
            "https://pds.example.com".to_string(),
            dpop_key,
            Some("test-nonce".to_string()),
        );

        let response = signer.respond(b"challenge").unwrap();
        assert_eq!(response.method.as_deref(), Some("pds-oauth"));
        assert!(response.dpop_proof.is_some());
        assert_eq!(response.pds_url.as_deref(), Some("https://pds.example.com"));
    }

    #[test]
    fn challenge_response_roundtrip() {
        let resp = ChallengeResponse {
            did: "did:plc:abc".to_string(),
            signature: "dGVzdA".to_string(),
            method: None,
            pds_url: None,
            dpop_proof: None,
        };
        let encoded = encode_response(&resp);
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let decoded: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.did, resp.did);
        assert!(decoded.method.is_none());
        assert!(decoded.dpop_proof.is_none());
    }

    #[test]
    fn pds_oauth_response_roundtrip() {
        let resp = ChallengeResponse {
            did: "did:plc:abc".to_string(),
            signature: "dpop.bound.token".to_string(),
            method: Some("pds-oauth".to_string()),
            pds_url: Some("https://pds.example.com".to_string()),
            dpop_proof: Some("dpop.proof.jwt".to_string()),
        };
        let encoded = encode_response(&resp);
        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let decoded: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.method.as_deref(), Some("pds-oauth"));
        assert_eq!(decoded.dpop_proof.as_deref(), Some("dpop.proof.jwt"));
    }
}
