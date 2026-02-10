//! IRC AT Protocol SDK
//!
//! A reusable client library for connecting to IRC servers that support
//! the ATPROTO-CHALLENGE SASL mechanism.
//!
//! # Modules
//!
//! - [`client`] — Async IRC client with SASL support
//! - [`auth`] — Challenge signing traits and implementations
//! - [`crypto`] — secp256k1 and ed25519 key operations
//! - [`did`] — DID document resolution (did:plc, did:web)
//! - [`pds`] — AT Protocol PDS client (session creation/verification)
//! - [`event`] — Events emitted by the client
//! - [`irc`] — IRC message parsing/formatting

pub mod auth;
pub mod client;
pub mod crypto;
pub mod did;
pub mod event;
pub mod irc;
pub mod media;
pub mod oauth;
pub mod pds;
