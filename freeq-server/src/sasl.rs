//! SASL ATPROTO-CHALLENGE authentication mechanism.
//!
//! Supports two verification methods:
//! 1. Cryptographic signature (default) — client signs challenge with their private key
//! 2. PDS session (method: "pds-session") — client provides a PDS access JWT
//!
//! Flow:
//! 1. Client sends AUTHENTICATE ATPROTO-CHALLENGE
//! 2. Server sends challenge: base64(json { session_id, nonce, timestamp })
//! 3. Client sends response: base64(json { did, signature, [method], [pds_url] })
//! 4. Server verifies via crypto or PDS session
//! 5. Server sends 903 (success) or 904 (failure)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use freeq_sdk::did::DidResolver;
use freeq_sdk::pds;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A challenge issued by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub session_id: String,
    pub nonce: String,
    pub timestamp: i64,
}

/// A client's response to a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub did: String,
    pub signature: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub pds_url: Option<String>,
    #[serde(default)]
    pub dpop_proof: Option<String>,
}

/// Stored challenge data: the struct for validation + raw bytes for signature verification.
struct StoredChallenge {
    challenge: Challenge,
    raw_bytes: Vec<u8>,
}

/// Tracks outstanding SASL challenges. Each challenge is single-use.
pub struct ChallengeStore {
    pending: Mutex<HashMap<String, StoredChallenge>>,
    timeout_secs: u64,
}

impl ChallengeStore {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout_secs,
        }
    }

    /// Generate a new challenge for a session. Returns the base64url-encoded challenge.
    pub fn create(&self, session_id: &str) -> String {
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        let challenge = Challenge {
            session_id: session_id.to_string(),
            nonce,
            timestamp: Utc::now().timestamp(),
        };

        let raw_bytes = serde_json::to_vec(&challenge).expect("challenge serialization");
        let encoded = URL_SAFE_NO_PAD.encode(&raw_bytes);

        self.pending.lock().unwrap().insert(
            session_id.to_string(),
            StoredChallenge {
                challenge,
                raw_bytes,
            },
        );

        encoded
    }

    /// Consume a challenge for verification. Returns None if the challenge
    /// doesn't exist, has already been used, or has expired.
    pub fn take(&self, session_id: &str) -> Option<(Challenge, Vec<u8>)> {
        let stored = self.pending.lock().unwrap().remove(session_id)?;

        let now = Utc::now().timestamp();
        if (now - stored.challenge.timestamp).unsigned_abs() > self.timeout_secs {
            tracing::warn!(session_id, "Challenge expired");
            return None;
        }

        Some((stored.challenge, stored.raw_bytes))
    }
}

/// Decode a client's SASL response from base64url JSON.
pub fn decode_response(encoded: &str) -> Option<ChallengeResponse> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Verify a challenge response. Dispatches to crypto or PDS verification.
pub async fn verify_response(
    challenge: &Challenge,
    challenge_bytes: &[u8],
    response: &ChallengeResponse,
    resolver: &DidResolver,
) -> Result<String, String> {
    if !response.did.starts_with("did:") {
        return Err("Invalid DID format".to_string());
    }

    match response.method.as_deref() {
        Some("pds-session") => verify_pds_session(challenge, response, resolver).await,
        Some("pds-oauth") => verify_pds_oauth(challenge, response, resolver).await,
        None | Some("crypto") => verify_crypto(challenge_bytes, response, resolver).await,
        Some(other) => Err(format!("Unsupported verification method: {other}")),
    }
}

/// Verify via cryptographic signature against DID document keys.
async fn verify_crypto(
    challenge_bytes: &[u8],
    response: &ChallengeResponse,
    resolver: &DidResolver,
) -> Result<String, String> {
    tracing::info!(did = %response.did, "Verifying SASL response (crypto)");

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&response.signature)
        .map_err(|e| format!("Invalid signature encoding: {e}"))?;

    let did_doc = resolver
        .resolve(&response.did)
        .await
        .map_err(|e| format!("Failed to resolve DID document: {e}"))?;

    if did_doc.id != response.did {
        return Err(format!(
            "DID document ID mismatch: expected {}, got {}",
            response.did, did_doc.id
        ));
    }

    let auth_keys = did_doc.authentication_keys();
    if auth_keys.is_empty() {
        return Err("No authentication keys found in DID document".to_string());
    }

    for (key_id, public_key) in &auth_keys {
        match public_key.verify(challenge_bytes, &sig_bytes) {
            Ok(()) => {
                tracing::info!(
                    did = %response.did,
                    key_id = %key_id,
                    key_type = public_key.key_type(),
                    "Crypto signature verified"
                );
                return Ok(response.did.clone());
            }
            Err(e) => {
                tracing::debug!(key_id = %key_id, "Key did not verify: {e}");
            }
        }
    }

    Err(format!(
        "Signature did not verify against any of {} authentication key(s)",
        auth_keys.len()
    ))
}

/// Verify via PDS session token.
///
/// 1. Resolve DID document to find PDS service endpoint
/// 2. Verify the claimed PDS URL matches the DID document
/// 3. Call PDS getSession to verify the token
/// 4. Confirm the DID matches
async fn verify_pds_session(
    _challenge: &Challenge,
    response: &ChallengeResponse,
    resolver: &DidResolver,
) -> Result<String, String> {
    tracing::info!(did = %response.did, "Verifying SASL response (pds-session)");

    let claimed_pds = response
        .pds_url
        .as_deref()
        .ok_or("pds-session method requires pds_url")?;

    // Resolve DID document
    let did_doc = resolver
        .resolve(&response.did)
        .await
        .map_err(|e| format!("Failed to resolve DID document: {e}"))?;

    if did_doc.id != response.did {
        return Err(format!(
            "DID document ID mismatch: expected {}, got {}",
            response.did, did_doc.id
        ));
    }

    // Verify PDS URL matches DID document
    let doc_pds = pds::pds_endpoint(&did_doc)
        .ok_or("No PDS service endpoint in DID document")?;

    // Normalize URLs for comparison (strip trailing slash)
    let normalize = |s: &str| s.trim_end_matches('/').to_string();
    if normalize(claimed_pds) != normalize(&doc_pds) {
        return Err(format!(
            "PDS URL mismatch: claimed {claimed_pds}, document says {doc_pds}"
        ));
    }

    // Verify the session with the PDS
    let session_info = pds::verify_session(claimed_pds, &response.signature)
        .await
        .map_err(|e| format!("PDS session verification failed: {e}"))?;

    // Confirm DID matches
    if session_info.did != response.did {
        return Err(format!(
            "PDS session DID mismatch: claimed {}, PDS says {}",
            response.did, session_info.did
        ));
    }

    tracing::info!(
        did = %response.did,
        handle = %session_info.handle,
        "PDS session verified"
    );
    Ok(response.did.clone())
}

/// Verify via DPoP-bound OAuth token.
///
/// The client provides both the access token and a DPoP proof that the
/// server can forward to the PDS's getSession endpoint.
async fn verify_pds_oauth(
    _challenge: &Challenge,
    response: &ChallengeResponse,
    resolver: &DidResolver,
) -> Result<String, String> {
    tracing::info!(did = %response.did, "Verifying SASL response (pds-oauth)");

    let claimed_pds = response
        .pds_url
        .as_deref()
        .ok_or("pds-oauth method requires pds_url")?;

    let dpop_proof = response
        .dpop_proof
        .as_deref()
        .ok_or("pds-oauth method requires dpop_proof")?;

    // Resolve DID document and verify PDS URL
    let did_doc = resolver
        .resolve(&response.did)
        .await
        .map_err(|e| format!("Failed to resolve DID document: {e}"))?;

    if did_doc.id != response.did {
        return Err(format!(
            "DID document ID mismatch: expected {}, got {}",
            response.did, did_doc.id
        ));
    }

    let doc_pds = pds::pds_endpoint(&did_doc)
        .ok_or("No PDS service endpoint in DID document")?;

    let normalize = |s: &str| s.trim_end_matches('/').to_string();
    if normalize(claimed_pds) != normalize(&doc_pds) {
        return Err(format!(
            "PDS URL mismatch: claimed {claimed_pds}, document says {doc_pds}"
        ));
    }

    // Call PDS getSession with DPoP token + proof
    let client = reqwest::Client::new();
    let get_session_url = format!(
        "{}/xrpc/com.atproto.server.getSession",
        claimed_pds.trim_end_matches('/')
    );

    let resp = client
        .get(&get_session_url)
        .header("Authorization", format!("DPoP {}", response.signature))
        .header("DPoP", dpop_proof)
        .send()
        .await
        .map_err(|e| format!("Failed to call PDS getSession: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("PDS OAuth verification failed ({status}): {text}"));
    }

    let session_info: pds::SessionInfo = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse PDS session response: {e}"))?;

    if session_info.did != response.did {
        return Err(format!(
            "PDS session DID mismatch: claimed {}, PDS says {}",
            response.did, session_info.did
        ));
    }

    tracing::info!(
        did = %response.did,
        handle = %session_info.handle,
        "PDS OAuth session verified"
    );
    Ok(response.did.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_create_and_take() {
        let store = ChallengeStore::new(60);
        let encoded = store.create("sess-1");
        assert!(!encoded.is_empty());

        let bytes = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
        let challenge: Challenge = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(challenge.session_id, "sess-1");

        let (taken, raw_bytes) = store.take("sess-1").unwrap();
        assert_eq!(taken.session_id, "sess-1");
        assert_eq!(raw_bytes, bytes);
    }

    #[test]
    fn challenge_single_use() {
        let store = ChallengeStore::new(60);
        store.create("sess-1");
        assert!(store.take("sess-1").is_some());
        // Replayed nonce — must fail
        assert!(store.take("sess-1").is_none());
    }

    #[test]
    fn challenge_expired() {
        // Create store with 0-second timeout — challenges expire immediately
        let store = ChallengeStore::new(0);
        store.create("sess-expired");
        // Even immediately, a 0-second window means the challenge is expired
        // (timestamp delta of 0 is NOT > 0, so it should still work at 0)
        // Let's use a store that's already "old":

        // Actually with 0 timeout, unsigned_abs() > 0 is false when delta is 0.
        // So we need to actually make time pass. Let's test with a very short timeout
        // and a manually set timestamp.

        // Direct test: create a stored challenge with an old timestamp
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let old_challenge = Challenge {
            session_id: "sess-old".to_string(),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            timestamp: Utc::now().timestamp() - 120, // 2 minutes ago
        };
        let raw = serde_json::to_vec(&old_challenge).unwrap();
        store.pending.lock().unwrap().insert(
            "sess-old".to_string(),
            StoredChallenge {
                challenge: old_challenge,
                raw_bytes: raw,
            },
        );

        // Should fail — challenge is expired (120s > 0s timeout)
        assert!(store.take("sess-old").is_none());
    }

    #[test]
    fn challenge_replay_different_session() {
        let store = ChallengeStore::new(60);
        store.create("sess-a");
        // Try to take with a different session ID — must fail
        assert!(store.take("sess-b").is_none());
        // Original should still work
        assert!(store.take("sess-a").is_some());
    }

    #[test]
    fn decode_response_roundtrip() {
        let resp = ChallengeResponse {
            did: "did:plc:abc123".to_string(),
            signature: "fakesig".to_string(),
            method: None,
            pds_url: None,
            dpop_proof: None,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&json);
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded.did, "did:plc:abc123");
    }

    #[test]
    fn decode_pds_session_response() {
        let resp = ChallengeResponse {
            did: "did:plc:abc".to_string(),
            signature: "jwt.token.here".to_string(),
            method: Some("pds-session".to_string()),
            pds_url: Some("https://pds.example.com".to_string()),
            dpop_proof: None,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&json);
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded.method.as_deref(), Some("pds-session"));
        assert_eq!(decoded.pds_url.as_deref(), Some("https://pds.example.com"));
    }

    #[tokio::test]
    async fn verify_with_real_crypto() {
        use freeq_sdk::crypto::PrivateKey;
        use freeq_sdk::did::{self, DidResolver};
        use std::collections::HashMap;

        let private_key = PrivateKey::generate_secp256k1();
        let multibase = private_key.public_key_multibase();
        let did = "did:plc:testuser123";
        let doc = did::make_test_did_document(did, &multibase);

        let mut docs = HashMap::new();
        docs.insert(did.to_string(), doc);
        let resolver = DidResolver::static_map(docs);

        let store = ChallengeStore::new(60);
        let _encoded = store.create("test-session");
        let (challenge, challenge_bytes) = store.take("test-session").unwrap();

        let signature = private_key.sign_base64url(&challenge_bytes);
        let response = ChallengeResponse {
            did: did.to_string(),
            signature,
            method: None,
            pds_url: None,
            dpop_proof: None,
        };

        let result = verify_response(&challenge, &challenge_bytes, &response, &resolver).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), did);
    }

    #[tokio::test]
    async fn verify_fails_with_wrong_key() {
        use freeq_sdk::crypto::PrivateKey;
        use freeq_sdk::did::{self, DidResolver};
        use std::collections::HashMap;

        let doc_key = PrivateKey::generate_secp256k1();
        let signer_key = PrivateKey::generate_secp256k1();
        let did = "did:plc:wrongkey";
        let doc = did::make_test_did_document(did, &doc_key.public_key_multibase());

        let mut docs = HashMap::new();
        docs.insert(did.to_string(), doc);
        let resolver = DidResolver::static_map(docs);

        let store = ChallengeStore::new(60);
        let _encoded = store.create("test-session");
        let (challenge, challenge_bytes) = store.take("test-session").unwrap();

        let signature = signer_key.sign_base64url(&challenge_bytes);
        let response = ChallengeResponse {
            did: did.to_string(),
            signature,
            method: None,
            pds_url: None,
            dpop_proof: None,
        };

        let result = verify_response(&challenge, &challenge_bytes, &response, &resolver).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("did not verify"));
    }
}
