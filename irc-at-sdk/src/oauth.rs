//! AT Protocol OAuth 2.0 authentication flow.
//!
//! Implements the browser-based OAuth flow for Bluesky/AT Protocol:
//! 1. Resolve user's PDS and authorization server
//! 2. Start a local HTTP server for the OAuth callback
//! 3. Open the user's browser to authorize
//! 4. Exchange the auth code for tokens (with DPoP binding)
//!
//! No passwords are entered in the terminal — the user authorizes
//! in their browser where they may already be logged in.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::did::DidResolver;
use crate::pds;

/// Result of a successful OAuth login.
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub did: String,
    pub handle: String,
    pub access_token: String,
    pub pds_url: String,
    pub dpop_key: DpopKey,
    /// DPoP nonce for the PDS (discovered during token exchange or pre-flight).
    pub dpop_nonce: Option<String>,
}

/// Serializable form of an OAuth session for disk caching.
#[derive(Serialize, Deserialize)]
struct CachedSession {
    did: String,
    handle: String,
    access_token: String,
    pds_url: String,
    dpop_key: String,
    dpop_nonce: Option<String>,
}

impl OAuthSession {
    /// Save session to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let cached = CachedSession {
            did: self.did.clone(),
            handle: self.handle.clone(),
            access_token: self.access_token.clone(),
            pds_url: self.pds_url.clone(),
            dpop_key: self.dpop_key.to_base64url(),
            dpop_nonce: self.dpop_nonce.clone(),
        };
        let json = serde_json::to_string_pretty(&cached)?;

        // Create parent dirs
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write with restrictive permissions (contains tokens)
        std::fs::write(path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Load session from a JSON file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let cached: CachedSession = serde_json::from_str(&json)?;
        let dpop_key = DpopKey::from_base64url(&cached.dpop_key)?;
        Ok(Self {
            did: cached.did,
            handle: cached.handle,
            access_token: cached.access_token,
            pds_url: cached.pds_url,
            dpop_key,
            dpop_nonce: cached.dpop_nonce,
        })
    }

    /// Validate the cached session by probing the PDS.
    /// Returns an updated session with a fresh DPoP nonce, or an error.
    pub async fn validate(mut self) -> Result<Self> {
        let nonce = probe_dpop_nonce(&self.pds_url, &self.access_token, &self.dpop_key).await;
        self.dpop_nonce = nonce;

        // Try actually calling getSession to verify the token still works
        let client = reqwest::Client::new();
        let url = format!(
            "{}/xrpc/com.atproto.server.getSession",
            self.pds_url.trim_end_matches('/')
        );
        let proof = self.dpop_key.proof(
            "GET", &url,
            self.dpop_nonce.as_deref(),
            Some(&self.access_token),
        )?;
        let resp = client
            .get(&url)
            .header("Authorization", format!("DPoP {}", self.access_token))
            .header("DPoP", &proof)
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Cached session is no longer valid ({})", resp.status());
        }

        Ok(self)
    }
}

/// Default path for the cached session file.
pub fn default_session_path(handle: &str) -> std::path::PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    config_dir.join("irc-at-tui").join(format!("{handle}.session.json"))
}

/// Authorization server metadata (RFC 8414 / AT Protocol extensions).
#[derive(Debug, Clone, Deserialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    pushed_authorization_request_endpoint: Option<String>,
}

/// Protected resource metadata for discovering the authorization server.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// Token response from the authorization server.
#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    sub: Option<String>,
}

/// A DPoP (Demonstrating Proof-of-Possession) key pair.
#[derive(Debug, Clone)]
pub struct DpopKey {
    signing_key: p256::ecdsa::SigningKey,
}

impl DpopKey {
    pub fn generate() -> Self {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        Self { signing_key }
    }

    /// Serialize the private key as base64url for caching.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.to_bytes())
    }

    /// Deserialize from base64url.
    pub fn from_base64url(s: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("Invalid DPoP key: {e}"))?;
        Ok(Self { signing_key })
    }

    fn jwk(&self) -> serde_json::Value {
        let verifying_key = self.signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        })
    }

    /// Create a DPoP proof JWT for a request.
    ///
    /// When `access_token` is provided, includes the `ath` (access token hash)
    /// claim as required by RFC 9449 §4.2 when the proof accompanies a token.
    pub fn proof(
        &self,
        method: &str,
        url: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<String> {
        use p256::ecdsa::{Signature, signature::Signer};

        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.jwk(),
        });

        let mut payload = serde_json::json!({
            "jti": generate_random_string(16),
            "htm": method,
            "htu": url,
            "iat": chrono::Utc::now().timestamp(),
        });
        if let Some(nonce) = nonce {
            payload["nonce"] = serde_json::Value::String(nonce.to_string());
        }
        if let Some(token) = access_token {
            // ath = base64url(SHA-256(access_token))
            let hash = Sha256::digest(token.as_bytes());
            payload["ath"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(hash));
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
        let signing_input = format!("{header_b64}.{payload_b64}");

        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Perform the full OAuth login flow for a Bluesky/AT Protocol handle.
///
/// Opens the user's browser for authorization. Returns an OAuthSession
/// that can be used to create a PdsSessionSigner.
pub async fn login(handle: &str) -> Result<OAuthSession> {
    let resolver = DidResolver::http();

    // 1. Resolve handle → DID → PDS
    tracing::info!("Resolving handle: {handle}");
    let did = resolver
        .resolve_handle(handle)
        .await
        .context("Failed to resolve handle")?;
    let did_doc = resolver
        .resolve(&did)
        .await
        .context("Failed to resolve DID document")?;
    let pds_url = pds::pds_endpoint(&did_doc).context("No PDS service endpoint in DID document")?;
    tracing::info!(did = %did, pds = %pds_url, "Resolved identity");

    // 2. Discover authorization server
    let auth_meta = discover_auth_server(&pds_url).await?;
    tracing::info!(issuer = %auth_meta.issuer, "Found authorization server");

    // 3. Start local callback server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // AT Protocol loopback OAuth:
    // - client_id must be "http://localhost" (magic value, not fetched)
    // - redirect_uri must use 127.0.0.1 IP (not "localhost"), no path
    let client_id = "http://localhost".to_string();
    let redirect_uri = format!("http://127.0.0.1:{port}");

    // 4. Generate PKCE and DPoP key
    let (code_verifier, code_challenge) = generate_pkce();
    let dpop_key = DpopKey::generate();
    let state = generate_random_string(16);

    // 5. PAR (Pushed Authorization Request) — required by Bluesky
    let par_endpoint = auth_meta
        .pushed_authorization_request_endpoint
        .as_deref()
        .context("Authorization server does not support PAR")?;

    let auth_url = push_authorization_request(
        par_endpoint,
        &auth_meta.authorization_endpoint,
        &client_id,
        &redirect_uri,
        &code_challenge,
        &state,
        handle,
        &dpop_key,
    )
    .await?;

    // 6. Open browser
    eprintln!("\nOpening browser for authorization...");
    eprintln!("If the browser doesn't open, visit:\n  {auth_url}\n");
    let _ = open::that(&auth_url);

    // 7. Wait for callback
    let auth_code = wait_for_callback(listener, &state).await?;
    eprintln!("Authorization received. Exchanging token...");

    // 8. Exchange code for tokens
    let (access_token, token_did) = exchange_code(
        &auth_meta.token_endpoint,
        &auth_code,
        &code_verifier,
        &redirect_uri,
        &client_id,
        &dpop_key,
    )
    .await?;

    // 9. Verify DID matches
    if let Some(ref token_did) = token_did
        && token_did != &did {
            bail!("DID mismatch: resolved {did} but token is for {token_did}");
        }

    // 10. Probe PDS getSession to discover the DPoP nonce
    //     The PDS will reject our first call but return the nonce we need.
    let dpop_nonce = probe_dpop_nonce(&pds_url, &access_token, &dpop_key).await;

    tracing::info!(did = %did, dpop_nonce = ?dpop_nonce, "OAuth login successful");
    Ok(OAuthSession {
        did,
        handle: handle.to_string(),
        access_token,
        pds_url,
        dpop_key,
        dpop_nonce,
    })
}

/// Discover the authorization server for a PDS.
async fn discover_auth_server(pds_url: &str) -> Result<AuthServerMetadata> {
    let client = reqwest::Client::new();

    let pr_url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_url.trim_end_matches('/')
    );
    let pr_meta: ProtectedResourceMetadata = client
        .get(&pr_url)
        .send()
        .await
        .context("Failed to fetch protected resource metadata")?
        .error_for_status()
        .context("Protected resource metadata request failed")?
        .json()
        .await
        .context("Failed to parse protected resource metadata")?;

    let auth_server = pr_meta
        .authorization_servers
        .first()
        .context("No authorization servers listed")?;

    let as_url = format!(
        "{}/.well-known/oauth-authorization-server",
        auth_server.trim_end_matches('/')
    );
    let auth_meta: AuthServerMetadata = client
        .get(&as_url)
        .send()
        .await
        .context("Failed to fetch authorization server metadata")?
        .error_for_status()
        .context("Authorization server metadata request failed")?
        .json()
        .await
        .context("Failed to parse authorization server metadata")?;

    Ok(auth_meta)
}

/// Pushed Authorization Request (PAR).
#[allow(clippy::too_many_arguments)]
async fn push_authorization_request(
    par_endpoint: &str,
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
    login_hint: &str,
    dpop_key: &DpopKey,
) -> Result<String> {
    let client = reqwest::Client::new();

    let params = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
        ("scope", "atproto transition:generic"),
        ("state", state),
        ("login_hint", login_hint),
    ];

    // Try without DPoP nonce first
    let dpop_proof = dpop_key.proof("POST", par_endpoint, None, None)?;
    let resp = client
        .post(par_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .context("PAR request failed")?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // If we got a use_dpop_nonce error, retry with the nonce
    if status.as_u16() == 400
        && let Some(ref nonce) = dpop_nonce {
            let dpop_proof_retry = dpop_key.proof("POST", par_endpoint, Some(nonce), None)?;
            let resp2 = client
                .post(par_endpoint)
                .header("DPoP", &dpop_proof_retry)
                .form(&params)
                .send()
                .await
                .context("PAR retry request failed")?;

            if !resp2.status().is_success() {
                let status = resp2.status();
                let text = resp2.text().await.unwrap_or_default();
                bail!("PAR failed ({status}): {text}");
            }

            let par_resp: serde_json::Value = resp2.json().await?;
            let request_uri = par_resp["request_uri"]
                .as_str()
                .context("No request_uri in PAR response")?;

            return Ok(format!(
                "{authorization_endpoint}?client_id={}&request_uri={}",
                urlencod(client_id),
                urlencod(request_uri),
            ));
        }

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("PAR failed ({status}): {text}");
    }

    let par_resp: serde_json::Value = resp.json().await?;
    let request_uri = par_resp["request_uri"]
        .as_str()
        .context("No request_uri in PAR response")?;

    Ok(format!(
        "{authorization_endpoint}?client_id={}&request_uri={}",
        urlencod(client_id),
        urlencod(request_uri),
    ))
}

/// Wait for the OAuth callback on the local HTTP server.
async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        let first_line = request.lines().next().unwrap_or("");
        let path = first_line.split_whitespace().nth(1).unwrap_or("/");

        // Parse query string from path
        let query = if let Some(q) = path.split('?').nth(1) {
            q
        } else {
            // Not a callback with query params — send 404 and keep waiting
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
            continue;
        };

        let params: HashMap<&str, &str> = query
            .split('&')
            .filter_map(|p| {
                let mut parts = p.splitn(2, '=');
                Some((parts.next()?, parts.next()?))
            })
            .collect();

        // Check for errors
        if let Some(error) = params.get("error") {
            let desc = params
                .get("error_description")
                .unwrap_or(&"Unknown error");
            let body = format!(
                "<html><body><h1>Authorization Failed</h1>\
                 <p>{error}: {desc}</p>\
                 <p>You can close this tab.</p></body></html>"
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;
            bail!("Authorization failed: {error}: {desc}");
        }

        if let (Some(code), Some(state)) = (params.get("code"), params.get("state")) {
            if *state != expected_state {
                bail!("State mismatch in OAuth callback");
            }

            let body = "<html><body><h1>Authorization Successful</h1>\
                        <p>You can close this tab and return to your terminal.</p>\
                        </body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await?;

            return Ok(code.to_string());
        }

        // No code/state — keep waiting
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
    }
}

/// Exchange an authorization code for tokens.
async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
    dpop_key: &DpopKey,
) -> Result<(String, Option<String>)> {
    let client = reqwest::Client::new();

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];

    // First attempt
    let dpop_proof = dpop_key.proof("POST", token_endpoint, None, None)?;
    let resp = client
        .post(token_endpoint)
        .header("DPoP", &dpop_proof)
        .form(&params)
        .send()
        .await
        .context("Token exchange request failed")?;

    let status = resp.status();
    let dpop_nonce = resp
        .headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Retry with DPoP nonce if needed
    if (status.as_u16() == 400 || status.as_u16() == 401) && dpop_nonce.is_some() {
        let nonce = dpop_nonce.as_deref().unwrap();
        let dpop_proof_retry = dpop_key.proof("POST", token_endpoint, Some(nonce), None)?;
        let resp2 = client
            .post(token_endpoint)
            .header("DPoP", &dpop_proof_retry)
            .form(&params)
            .send()
            .await
            .context("Token exchange retry failed")?;

        if !resp2.status().is_success() {
            let status = resp2.status();
            let text = resp2.text().await.unwrap_or_default();
            bail!("Token exchange failed ({status}): {text}");
        }

        let token_resp: TokenResponse =
            resp2.json().await.context("Failed to parse token response")?;
        return Ok((token_resp.access_token, token_resp.sub));
    }

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("Token exchange failed ({status}): {text}");
    }

    let token_resp: TokenResponse = resp.json().await.context("Failed to parse token response")?;
    Ok((token_resp.access_token, token_resp.sub))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn generate_pkce() -> (String, String) {
    let verifier = generate_random_string(32);
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

fn generate_random_string(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Probe the PDS getSession endpoint to discover the required DPoP nonce.
/// Returns None if no nonce is required or if the probe fails.
async fn probe_dpop_nonce(pds_url: &str, access_token: &str, dpop_key: &DpopKey) -> Option<String> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/xrpc/com.atproto.server.getSession",
        pds_url.trim_end_matches('/')
    );

    // Make a request without a nonce — the PDS will reject it but return the nonce
    let proof = dpop_key.proof("GET", &url, None, Some(access_token)).ok()?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", &proof)
        .send()
        .await
        .ok()?;

    resp.headers()
        .get("dpop-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn urlencod(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}
