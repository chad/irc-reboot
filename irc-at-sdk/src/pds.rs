//! AT Protocol PDS (Personal Data Server) client.
//!
//! Handles:
//! - Session creation (login with handle + app password)
//! - Session verification (for server-side SASL checks)
//! - PDS service endpoint discovery from DID documents

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::did::{DidDocument, DidResolver};

/// A PDS session obtained by authenticating with an app password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdsSession {
    pub did: String,
    pub handle: String,
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
}

/// Response from getSession — verifies a session is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub handle: String,
}

/// Extract the PDS service endpoint URL from a DID document.
pub fn pds_endpoint(doc: &DidDocument) -> Option<String> {
    doc.service.iter().find_map(|svc| {
        if svc.service_type == "AtprotoPersonalDataServer" {
            Some(svc.service_endpoint.clone())
        } else {
            None
        }
    })
}

/// Authenticate to a PDS and get a session.
///
/// This is the standard AT Protocol login flow using an app password.
///
/// Steps:
/// 1. If `identifier` is a handle, resolve it to find the PDS
/// 2. Authenticate via `com.atproto.server.createSession`
/// 3. Return the session with DID, handle, and access JWT
pub async fn create_session(
    identifier: &str,
    password: &str,
    resolver: &DidResolver,
) -> Result<(PdsSession, String)> {
    let client = reqwest::Client::new();

    // Resolve identifier to DID and find PDS
    let did = if identifier.starts_with("did:") {
        identifier.to_string()
    } else {
        // It's a handle — resolve to DID
        resolver
            .resolve_handle(identifier)
            .await
            .context("Failed to resolve handle to DID")?
    };

    // Resolve DID document to find PDS endpoint
    let did_doc = resolver
        .resolve(&did)
        .await
        .context("Failed to resolve DID document")?;

    let pds_url = pds_endpoint(&did_doc)
        .context("No PDS service endpoint found in DID document")?;

    tracing::info!(did = %did, pds = %pds_url, "Authenticating to PDS");

    // Call createSession
    let url = format!("{pds_url}/xrpc/com.atproto.server.createSession");
    let body = serde_json::json!({
        "identifier": identifier,
        "password": password,
    });

    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("Failed to connect to PDS")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("PDS authentication failed ({status}): {text}");
    }

    let session: PdsSession = resp
        .json()
        .await
        .context("Failed to parse PDS session response")?;

    tracing::info!(did = %session.did, handle = %session.handle, "PDS session created");
    Ok((session, pds_url))
}

/// Verify a PDS session by calling getSession.
///
/// Used by the server to verify a client's PDS session token.
/// Returns the session info (DID, handle) if valid.
pub async fn verify_session(pds_url: &str, access_jwt: &str) -> Result<SessionInfo> {
    let client = reqwest::Client::new();
    let url = format!("{pds_url}/xrpc/com.atproto.server.getSession");

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {access_jwt}"))
        .send()
        .await
        .context("Failed to connect to PDS for session verification")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        bail!("PDS session verification failed ({status}): {text}");
    }

    let info: SessionInfo = resp
        .json()
        .await
        .context("Failed to parse PDS session info")?;

    Ok(info)
}
