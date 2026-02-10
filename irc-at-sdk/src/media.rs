//! Rich media support for IRC messages.
//!
//! Uses IRCv3 message tags to carry media metadata alongside plain-text
//! fallback in the PRIVMSG body. This gives multipart/alternative semantics:
//! - Plain clients see the text + URL
//! - Rich clients parse the tags and render inline previews
//!
//! Media is hosted externally (AT Protocol PDS blob storage, or any URL).
//! The IRC server never handles media bytes — it just relays tagged messages.

use std::collections::HashMap;

use anyhow::Result;
use reqwest::header;

/// Metadata for a media attachment.
#[derive(Debug, Clone)]
pub struct MediaAttachment {
    /// MIME content type (e.g. "image/jpeg", "video/mp4").
    pub content_type: String,
    /// URL where the media can be fetched.
    pub url: String,
    /// Alt text / description.
    pub alt: Option<String>,
    /// Width in pixels.
    pub width: Option<u32>,
    /// Height in pixels.
    pub height: Option<u32>,
    /// Blurhash placeholder string.
    pub blurhash: Option<String>,
    /// File size in bytes.
    pub size: Option<u64>,
    /// Original filename.
    pub filename: Option<String>,
}

impl MediaAttachment {
    /// Encode as IRCv3 message tags.
    pub fn to_tags(&self) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        tags.insert("content-type".to_string(), self.content_type.clone());
        tags.insert("media-url".to_string(), self.url.clone());
        if let Some(ref alt) = self.alt {
            tags.insert("media-alt".to_string(), alt.clone());
        }
        if let Some(w) = self.width {
            tags.insert("media-w".to_string(), w.to_string());
        }
        if let Some(h) = self.height {
            tags.insert("media-h".to_string(), h.to_string());
        }
        if let Some(ref bh) = self.blurhash {
            tags.insert("media-blurhash".to_string(), bh.clone());
        }
        if let Some(sz) = self.size {
            tags.insert("media-size".to_string(), sz.to_string());
        }
        if let Some(ref name) = self.filename {
            tags.insert("media-filename".to_string(), name.clone());
        }
        tags
    }

    /// Parse from IRCv3 message tags.
    pub fn from_tags(tags: &HashMap<String, String>) -> Option<Self> {
        let content_type = tags.get("content-type")?.clone();
        let url = tags.get("media-url")?.clone();
        Some(Self {
            content_type,
            url,
            alt: tags.get("media-alt").cloned(),
            width: tags.get("media-w").and_then(|v| v.parse().ok()),
            height: tags.get("media-h").and_then(|v| v.parse().ok()),
            blurhash: tags.get("media-blurhash").cloned(),
            size: tags.get("media-size").and_then(|v| v.parse().ok()),
            filename: tags.get("media-filename").cloned(),
        })
    }

    /// Generate the plain-text fallback for the PRIVMSG body.
    pub fn fallback_text(&self) -> String {
        match &self.alt {
            Some(alt) => format!("{alt} {}", self.url),
            None => self.url.clone(),
        }
    }

    /// Is this an image type?
    pub fn is_image(&self) -> bool {
        self.content_type.starts_with("image/")
    }

    /// Is this a video type?
    pub fn is_video(&self) -> bool {
        self.content_type.starts_with("video/")
    }

    /// Is this an audio type?
    pub fn is_audio(&self) -> bool {
        self.content_type.starts_with("audio/")
    }
}

/// A link preview (OpenGraph-style metadata).
#[derive(Debug, Clone)]
pub struct LinkPreview {
    /// The URL being previewed.
    pub url: String,
    /// Page title.
    pub title: Option<String>,
    /// Description text.
    pub description: Option<String>,
    /// Thumbnail image URL.
    pub thumb_url: Option<String>,
}

impl LinkPreview {
    pub fn to_tags(&self) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        tags.insert("content-type".to_string(), "text/x-link-preview".to_string());
        tags.insert("media-url".to_string(), self.url.clone());
        if let Some(ref t) = self.title {
            tags.insert("link-title".to_string(), t.clone());
        }
        if let Some(ref d) = self.description {
            tags.insert("link-desc".to_string(), d.clone());
        }
        if let Some(ref thumb) = self.thumb_url {
            tags.insert("link-thumb".to_string(), thumb.clone());
        }
        tags
    }

    pub fn from_tags(tags: &HashMap<String, String>) -> Option<Self> {
        if tags.get("content-type")?.as_str() != "text/x-link-preview" {
            return None;
        }
        Some(Self {
            url: tags.get("media-url")?.clone(),
            title: tags.get("link-title").cloned(),
            description: tags.get("link-desc").cloned(),
            thumb_url: tags.get("link-thumb").cloned(),
        })
    }
}

/// Upload a blob to an AT Protocol PDS and return the CDN URL.
///
/// Requires an authenticated session (access token + optional DPoP).
/// Handles DPoP nonce discovery automatically (retries on `use_dpop_nonce` error).
pub async fn upload_blob_to_pds(
    pds_url: &str,
    access_token: &str,
    dpop_key: Option<&crate::oauth::DpopKey>,
    dpop_nonce: Option<&str>,
    content_type: &str,
    data: &[u8],
) -> Result<BlobUploadResult> {
    let client = reqwest::Client::new();
    let url = format!("{}/xrpc/com.atproto.repo.uploadBlob", pds_url.trim_end_matches('/'));

    let mut current_nonce = dpop_nonce.map(|s| s.to_string());

    // Retry loop for DPoP nonce discovery (PDS may require a fresh nonce)
    for attempt in 0..3 {
        let mut req = client.post(&url)
            .header(header::CONTENT_TYPE, content_type)
            .body(data.to_vec());

        if let Some(key) = dpop_key {
            let proof = key.proof("POST", &url, current_nonce.as_deref(), Some(access_token))?;
            req = req
                .header("Authorization", format!("DPoP {access_token}"))
                .header("DPoP", proof);
        } else {
            req = req.header("Authorization", format!("Bearer {access_token}"));
        }

        let resp = req.send().await?;

        // Check for DPoP nonce error — PDS sends 401 with a new nonce
        if (resp.status() == 401 || resp.status() == 400)
            && let Some(new_nonce) = resp.headers().get("dpop-nonce")
            && attempt < 2
        {
            current_nonce = Some(new_nonce.to_str().unwrap_or("").to_string());
            continue; // Retry with fresh nonce
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Blob upload failed ({status}): {body}");
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Blob upload failed ({status}): {body}");
        }

        let result: serde_json::Value = resp.json().await?;
        let blob = &result["blob"];

        let cid = blob["ref"]["$link"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("No CID in upload response"))?
            .to_string();

        let size = blob["size"].as_u64().unwrap_or(data.len() as u64);
        let mime = blob["mimeType"].as_str().unwrap_or(content_type).to_string();

        return Ok(BlobUploadResult {
            cid,
            size,
            mime_type: mime,
        });
    }

    anyhow::bail!("Blob upload failed after retries")
}

/// Result of a blob upload to PDS.
#[derive(Debug, Clone)]
pub struct BlobUploadResult {
    /// Content identifier (CID) of the uploaded blob.
    pub cid: String,
    /// Size in bytes.
    pub size: u64,
    /// MIME type.
    pub mime_type: String,
}

impl BlobUploadResult {
    /// Construct the Bluesky CDN URL for this blob.
    ///
    /// Format: `https://cdn.bsky.app/img/feed_thumbnail/plain/{did}/{cid}@jpeg`
    /// For full size: `https://cdn.bsky.app/img/feed_fullsize/plain/{did}/{cid}@jpeg`
    pub fn cdn_url(&self, did: &str) -> String {
        let ext = match self.mime_type.as_str() {
            "image/png" => "png",
            "image/webp" => "webp",
            _ => "jpeg",
        };
        format!(
            "https://cdn.bsky.app/img/feed_fullsize/plain/{did}/{cid}@{ext}",
            did = did,
            cid = self.cid,
            ext = ext,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_attachment_roundtrip() {
        let media = MediaAttachment {
            content_type: "image/jpeg".to_string(),
            url: "https://cdn.bsky.app/img/example.jpg".to_string(),
            alt: Some("A sunset".to_string()),
            width: Some(1200),
            height: Some(800),
            blurhash: Some("LEHV6nWB2yk8".to_string()),
            size: Some(45000),
            filename: Some("sunset.jpg".to_string()),
        };

        let tags = media.to_tags();
        let parsed = MediaAttachment::from_tags(&tags).unwrap();

        assert_eq!(parsed.content_type, "image/jpeg");
        assert_eq!(parsed.url, media.url);
        assert_eq!(parsed.alt.as_deref(), Some("A sunset"));
        assert_eq!(parsed.width, Some(1200));
        assert_eq!(parsed.height, Some(800));
        assert_eq!(parsed.blurhash.as_deref(), Some("LEHV6nWB2yk8"));
        assert_eq!(parsed.size, Some(45000));
        assert_eq!(parsed.filename.as_deref(), Some("sunset.jpg"));
    }

    #[test]
    fn media_fallback_text() {
        let media = MediaAttachment {
            content_type: "image/jpeg".to_string(),
            url: "https://example.com/img.jpg".to_string(),
            alt: Some("My photo".to_string()),
            width: None, height: None, blurhash: None, size: None, filename: None,
        };
        assert_eq!(media.fallback_text(), "My photo https://example.com/img.jpg");

        let no_alt = MediaAttachment {
            alt: None,
            ..media
        };
        assert_eq!(no_alt.fallback_text(), "https://example.com/img.jpg");
    }

    #[test]
    fn link_preview_roundtrip() {
        let preview = LinkPreview {
            url: "https://example.com/article".to_string(),
            title: Some("Great Article".to_string()),
            description: Some("An interesting read".to_string()),
            thumb_url: Some("https://example.com/thumb.jpg".to_string()),
        };

        let tags = preview.to_tags();
        let parsed = LinkPreview::from_tags(&tags).unwrap();

        assert_eq!(parsed.url, preview.url);
        assert_eq!(parsed.title.as_deref(), Some("Great Article"));
        assert_eq!(parsed.description.as_deref(), Some("An interesting read"));
    }

    #[test]
    fn type_checks() {
        let img = MediaAttachment {
            content_type: "image/png".to_string(),
            url: String::new(), alt: None, width: None, height: None,
            blurhash: None, size: None, filename: None,
        };
        assert!(img.is_image());
        assert!(!img.is_video());

        let vid = MediaAttachment {
            content_type: "video/mp4".to_string(),
            ..img.clone()
        };
        assert!(vid.is_video());
    }
}
