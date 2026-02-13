//! Integration tests: server + SDK client in-process.
//!
//! These tests start a real TCP server, connect real SDK clients, and verify
//! the full SASL ATPROTO-CHALLENGE flow end-to-end.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use freeq_sdk::auth::{ChallengeSigner, KeySigner};
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::crypto::PrivateKey;
use freeq_sdk::did::{self, DidResolver};
use freeq_sdk::event::Event;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Helper: start a server on a random port with a static DID resolver.
async fn start_test_server(
    resolver: DidResolver,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

/// Helper: wait for a specific event, with timeout.
async fn expect_event(
    events: &mut mpsc::Receiver<Event>,
    timeout_ms: u64,
    predicate: impl Fn(&Event) -> bool,
    description: &str,
) -> Event {
    let deadline = Duration::from_millis(timeout_ms);
    let start = tokio::time::Instant::now();
    loop {
        match timeout(deadline.saturating_sub(start.elapsed()), events.recv()).await {
            Ok(Some(event)) => {
                if predicate(&event) {
                    return event;
                }
                // Not the event we want, keep going
            }
            Ok(None) => panic!("Channel closed while waiting for: {description}"),
            Err(_) => panic!("Timeout waiting for: {description}"),
        }
    }
}

fn empty_resolver() -> DidResolver {
    DidResolver::static_map(HashMap::new())
}

// ── Test: Guest connection (no SASL) ────────────────────────────────

#[tokio::test]
async fn guest_connection() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "guest1".to_string(),
        user: "guest1".to_string(),
        realname: "Guest User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, None);

    // Should get Connected then Registered
    expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
    let reg = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    if let Event::Registered { nick } = reg {
        assert_eq!(nick, "guest1");
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated connection with secp256k1 ───────────────────

#[tokio::test]
async fn authenticated_secp256k1() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testsecp256k1";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        did_str.to_string(),
        private_key,
    ));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "authuser".to_string(),
        user: "authuser".to_string(),
        realname: "Auth User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
    let auth = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;

    if let Event::Authenticated { did } = auth {
        assert_eq!(did, did_str);
    }

    let reg = expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    if let Event::Registered { nick } = reg {
        assert_eq!(nick, "authuser");
    }

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated connection with ed25519 ─────────────────────

#[tokio::test]
async fn authenticated_ed25519() {
    let private_key = PrivateKey::generate_ed25519();
    let did_str = "did:plc:tested25519";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        did_str.to_string(),
        private_key,
    ));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "eduser".to_string(),
        user: "eduser".to_string(),
        realname: "Ed25519 User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Authenticated { .. }),
        "Authenticated",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Auth fails with wrong key ─────────────────────────────────

#[tokio::test]
async fn auth_fails_wrong_key() {
    // DID document has one key, client signs with a different key
    let doc_key = PrivateKey::generate_secp256k1();
    let signer_key = PrivateKey::generate_secp256k1();

    let did_str = "did:plc:wrongkey";
    let doc = did::make_test_did_document(did_str, &doc_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        did_str.to_string(),
        signer_key,
    ));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "baduser".to_string(),
        user: "baduser".to_string(),
        realname: "Bad User".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;

    // Should get AuthFailed
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::AuthFailed { .. }),
        "AuthFailed",
    )
    .await;

    // Should still register as guest (fallback)
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered as guest",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Auth fails with unknown DID ───────────────────────────────

#[tokio::test]
async fn auth_fails_unknown_did() {
    // Resolver has no documents — DID can't be resolved
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let private_key = PrivateKey::generate_secp256k1();
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        "did:plc:doesnotexist".to_string(),
        private_key,
    ));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "unknown".to_string(),
        user: "unknown".to_string(),
        realname: "Unknown DID".to_string(),
        ..Default::default()
    };

    let (handle, mut events) = client::connect(config, Some(signer));

    expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::AuthFailed { .. }),
        "AuthFailed",
    )
    .await;
    expect_event(
        &mut events,
        2000,
        |e| matches!(e, Event::Registered { .. }),
        "Registered as guest",
    )
    .await;

    handle.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Two clients in the same channel can exchange messages ──────

#[tokio::test]
async fn channel_messaging() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect client 1
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;

    // Connect client 2
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;

    // Both join #test
    handle1.join("#test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { channel, nick } if channel == "#test" && nick == "alice"),
        "Alice joined",
    )
    .await;

    handle2.join("#test").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Joined { channel, nick } if channel == "#test" && nick == "bob"),
        "Bob joined",
    )
    .await;

    // Alice also sees Bob join
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Joined { channel, nick } if channel == "#test" && nick == "bob"),
        "Alice sees Bob join",
    )
    .await;

    // Alice sends a message
    handle1.privmsg("#test", "hello bob!").await.unwrap();

    // Bob should receive it
    let msg = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::Message { target, .. } if target == "#test"),
        "Bob receives message",
    )
    .await;

    if let Event::Message { from, target, text, .. } = msg {
        assert_eq!(from, "alice");
        assert_eq!(target, "#test");
        assert_eq!(text, "hello bob!");
    }

    // Bob replies
    handle2.privmsg("#test", "hi alice!").await.unwrap();

    let msg = expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Message { target, .. } if target == "#test"),
        "Alice receives reply",
    )
    .await;

    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "bob");
        assert_eq!(text, "hi alice!");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Authenticated + guest in same channel ─────────────────────

#[tokio::test]
async fn mixed_auth_and_guest_in_channel() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:mixedtest";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Authenticated client
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(
        did_str.to_string(),
        private_key,
    ));
    let config_auth = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "authed".to_string(),
        user: "authed".to_string(),
        realname: "Authenticated".to_string(),
        ..Default::default()
    };
    let (handle_auth, mut events_auth) = client::connect(config_auth, Some(signer));
    expect_event(&mut events_auth, 2000, |e| matches!(e, Event::Authenticated { .. }), "Auth").await;
    expect_event(&mut events_auth, 2000, |e| matches!(e, Event::Registered { .. }), "Reg").await;

    // Guest client
    let config_guest = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "guest".to_string(),
        user: "guest".to_string(),
        realname: "Guest".to_string(),
        ..Default::default()
    };
    let (handle_guest, mut events_guest) = client::connect(config_guest, None);
    expect_event(&mut events_guest, 2000, |e| matches!(e, Event::Registered { .. }), "Guest reg").await;

    // Both join
    handle_auth.join("#mixed").await.unwrap();
    expect_event(&mut events_auth, 2000, |e| matches!(e, Event::Joined { .. }), "Auth join").await;

    handle_guest.join("#mixed").await.unwrap();
    expect_event(&mut events_guest, 2000, |e| matches!(e, Event::Joined { .. }), "Guest join").await;

    // Guest sends message, authed user receives it
    handle_guest.privmsg("#mixed", "from guest").await.unwrap();
    let msg = expect_event(
        &mut events_auth,
        2000,
        |e| matches!(e, Event::Message { target, .. } if target == "#mixed"),
        "Authed receives from guest",
    )
    .await;
    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "guest");
        assert_eq!(text, "from guest");
    }

    // Authed sends message, guest receives it
    handle_auth.privmsg("#mixed", "from authed").await.unwrap();
    let msg = expect_event(
        &mut events_guest,
        2000,
        |e| matches!(e, Event::Message { target, .. } if target == "#mixed"),
        "Guest receives from authed",
    )
    .await;
    if let Event::Message { from, text, .. } = msg {
        assert_eq!(from, "authed");
        assert_eq!(text, "from authed");
    }

    handle_auth.quit(None).await.unwrap();
    handle_guest.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Nick collision ────────────────────────────────────────────

#[tokio::test]
async fn nick_collision() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "samename".to_string(),
        user: "user1".to_string(),
        realname: "User 1".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "User1 registered").await;

    // Second client with same nick — should get a raw 433 (ERR_NICKNAMEINUSE)
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "samename".to_string(),
        user: "user2".to_string(),
        realname: "User 2".to_string(),
        ..Default::default()
    };
    let (_handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Connected), "User2 connected").await;

    // Should see a 433 in the raw lines
    let found_433 = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("433")),
        "Nick in use error",
    )
    .await;
    assert!(matches!(found_433, Event::RawLine(_)));

    handle1.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TOPIC ─────────────────────────────────────────────────────

#[tokio::test]
async fn channel_topic() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Connect user1
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;

    // Join channel
    handle1.join("#test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Set topic
    handle1.raw("TOPIC #test :Hello World").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Topic set",
    ).await;

    // Query topic
    handle1.raw("TOPIC #test").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Topic query returned",
    ).await;

    // Connect user2 — should see topic on join
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;

    handle2.join("#test").await.unwrap();

    // Bob should receive the topic on join
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#test" && topic == "Hello World"),
        "Bob sees topic on join",
    ).await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Channel ops (auto-op creator, +o/-o, KICK) ────────────────

#[tokio::test]
async fn channel_ops_and_kick() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel — should be auto-opped
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;

    handle1.join("#ops-test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Verify Alice has @ in NAMES
    let names_event = expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::Names { channel, .. } if channel == "#ops-test"),
        "Alice NAMES",
    ).await;
    if let Event::Names { nicks, .. } = names_event {
        assert!(nicks.iter().any(|n| n == "@alice"), "Alice should be @alice, got: {nicks:?}");
    }

    // Bob joins — not opped
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;

    handle2.join("#ops-test").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Bob tries to kick Alice — should fail (not op)
    handle2.raw("KICK #ops-test alice :bye").await.unwrap();
    let err = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("482")),
        "Bob gets chanop error",
    ).await;
    assert!(matches!(err, Event::RawLine(_)));

    // Alice ops Bob
    handle1.raw("MODE #ops-test +o bob").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, arg, .. } if mode == "+o" && arg.as_deref() == Some("bob")),
        "Alice sees +o bob",
    ).await;

    // Charlie joins
    let config3 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "charlie".to_string(),
        user: "charlie".to_string(),
        realname: "Charlie".to_string(),
        ..Default::default()
    };
    let (handle3, mut events3) = client::connect(config3, None);
    expect_event(&mut events3, 2000, |e| matches!(e, Event::Registered { .. }), "Charlie registered").await;

    handle3.join("#ops-test").await.unwrap();
    expect_event(&mut events3, 2000, |e| matches!(e, Event::Joined { .. }), "Charlie joined").await;

    // Bob (now op) kicks Charlie
    handle2.raw("KICK #ops-test charlie :troublemaker").await.unwrap();
    let kick_event = expect_event(
        &mut events3,
        2000,
        |e| matches!(e, Event::Kicked { nick, by, .. } if nick == "charlie" && by == "bob"),
        "Charlie sees kick",
    ).await;
    assert!(matches!(kick_event, Event::Kicked { reason, .. } if reason == "troublemaker"));

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    handle3.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn topic_lock_mode() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel (auto-op)
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#lock-test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Bob joins
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#lock-test").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Bob can set topic (no +t yet)
    handle2.raw("TOPIC #lock-test :Bob's topic").await.unwrap();
    expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic == "Bob's topic"),
        "Bob sets topic",
    ).await;

    // Alice locks topic (+t)
    handle1.raw("MODE #lock-test +t").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+t"),
        "Alice sees +t",
    ).await;

    // Bob tries to set topic — should fail
    handle2.raw("TOPIC #lock-test :Nope").await.unwrap();
    let err = expect_event(
        &mut events2,
        2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("482")),
        "Bob gets chanop error on topic",
    ).await;
    assert!(matches!(err, Event::RawLine(_)));

    // Alice can still set topic
    handle1.raw("TOPIC #lock-test :Alice's topic").await.unwrap();
    expect_event(
        &mut events1,
        2000,
        |e| matches!(e, Event::TopicChanged { topic, .. } if topic == "Alice's topic"),
        "Alice sets topic with +t",
    ).await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Ban (hostmask and DID-based) ──────────────────────────────

#[tokio::test]
async fn ban_hostmask() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#ban-test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Ban bob's hostmask pattern
    handle1.raw("MODE #ban-test +b bob!*@*").await.unwrap();
    expect_event(
        &mut events1, 2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+b"),
        "Ban set",
    ).await;

    // Bob tries to join — should be banned
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;

    handle2.join("#ban-test").await.unwrap();
    // Should get 474 ERR_BANNEDFROMCHAN
    expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "Bob banned",
    ).await;

    // Alice removes ban
    handle1.raw("MODE #ban-test -b bob!*@*").await.unwrap();
    expect_event(
        &mut events1, 2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "-b"),
        "Ban removed",
    ).await;

    // Bob can now join
    handle2.join("#ban-test").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joins after unban").await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn ban_by_did() {
    // Set up a resolver with a DID for alice
    let private_key = PrivateKey::generate_secp256k1();
    let did = "did:plc:testban123";
    let did_doc = did::make_test_did_document(did, &private_key.public_key_multibase());

    let mut map = HashMap::new();
    map.insert(did.to_string(), did_doc);
    let resolver = DidResolver::static_map(map);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Bob creates channel (no auth)
    let config_bob = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle_bob, mut events_bob) = client::connect(config_bob, None);
    expect_event(&mut events_bob, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle_bob.join("#did-ban").await.unwrap();
    expect_event(&mut events_bob, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Alice connects with auth
    let signer = Arc::new(KeySigner::new(did.to_string(), private_key));
    let config_alice = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle_alice, mut events_alice) = client::connect(config_alice, Some(signer));
    expect_event(&mut events_alice, 2000, |e| matches!(e, Event::Authenticated { .. }), "Alice authed").await;
    expect_event(&mut events_alice, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;

    // Alice joins
    handle_alice.join("#did-ban").await.unwrap();
    expect_event(&mut events_alice, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Bob bans Alice by DID
    handle_bob.raw(&format!("MODE #did-ban +b {did}")).await.unwrap();
    expect_event(
        &mut events_bob, 2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+b"),
        "DID ban set",
    ).await;

    // Kick Alice
    handle_bob.raw("KICK #did-ban alice :DID banned").await.unwrap();
    expect_event(&mut events_alice, 2000, |e| matches!(e, Event::Kicked { .. }), "Alice kicked").await;

    // Alice tries to rejoin — should be DID-banned
    handle_alice.join("#did-ban").await.unwrap();
    expect_event(
        &mut events_alice, 2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "Alice DID-banned",
    ).await;

    handle_bob.quit(None).await.unwrap();
    handle_alice.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Invite-only channel ───────────────────────────────────────

#[tokio::test]
async fn invite_only_channel() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates channel, sets +i
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#invite-test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    handle1.raw("MODE #invite-test +i").await.unwrap();
    expect_event(
        &mut events1, 2000,
        |e| matches!(e, Event::ModeChanged { mode, .. } if mode == "+i"),
        "+i set",
    ).await;

    // Bob tries to join — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;

    handle2.join("#invite-test").await.unwrap();
    expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "Bob rejected (invite only)",
    ).await;

    // Alice invites Bob
    handle1.raw("INVITE bob #invite-test").await.unwrap();

    // Bob should receive invite notification
    expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Invited { channel, .. } if channel == "#invite-test"),
        "Bob invited",
    ).await;

    // Now Bob can join
    handle2.join("#invite-test").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joins after invite").await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Message history replay on JOIN ────────────────────────────

#[tokio::test]
async fn message_history_replay() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice joins and sends messages
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#history").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    handle1.privmsg("#history", "first message").await.unwrap();
    handle1.privmsg("#history", "second message").await.unwrap();
    // Small delay so messages are stored
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Bob joins — should see replayed messages
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#history").await.unwrap();

    // Bob should receive the history as messages
    let msg1 = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Message { text, .. } if text == "first message"),
        "Bob sees first history message",
    ).await;
    assert!(matches!(msg1, Event::Message { .. }));

    let msg2 = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Message { text, .. } if text == "second message"),
        "Bob sees second history message",
    ).await;
    assert!(matches!(msg2, Event::Message { .. }));

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Nick ownership by DID ─────────────────────────────────────

#[tokio::test]
async fn nick_ownership() {
    let private_key = PrivateKey::generate_secp256k1();
    let did = "did:plc:nickowner";
    let doc = did::make_test_did_document(did, &private_key.public_key_multibase());

    let mut map = HashMap::new();
    map.insert(did.to_string(), doc);
    let resolver = DidResolver::static_map(map);

    let (addr, server_handle) = start_test_server(resolver).await;

    // Alice authenticates and claims nick "alice"
    let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did.to_string(), private_key));
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, Some(signer));
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Authenticated { .. }), "Alice authed").await;
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;

    // Alice disconnects
    handle1.quit(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Guest tries to take "alice" — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "imposter".to_string(),
        realname: "Imposter".to_string(),
        ..Default::default()
    };
    let (_handle2, mut events2) = client::connect(config2, None);

    // Guest enters CAP negotiation (message-tags), so nick is provisionally allowed.
    // At registration, the nick ownership check renames them to GuestXXXX.
    // They should get a Registered event with a Guest nick, not "alice".
    let reg = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Registered { nick } if nick != "alice"),
        "Imposter registered with different nick",
    ).await;
    if let Event::Registered { nick } = reg {
        assert!(nick.starts_with("Guest"), "Expected GuestXXXX, got {nick}");
    }

    server_handle.abort();
}

// ── Test: QUIT broadcast ────────────────────────────────────────────

#[tokio::test]
async fn quit_broadcast() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#quit-test").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#quit-test").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Drain bob's join event from alice's stream
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"), "Alice sees bob join").await;

    // Bob quits
    handle2.quit(Some("goodbye")).await.unwrap();

    // Alice should see bob's QUIT
    expect_event(
        &mut events1, 2000,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == "bob"),
        "Alice sees bob quit",
    ).await;

    handle1.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Expired challenge is rejected ─────────────────────────────

#[tokio::test]
async fn auth_fails_expired_challenge() {
    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testexpired";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    // Server with 1-second challenge timeout
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 1,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    let (addr, server_handle) = server.start().await.unwrap();

    // Use raw TCP to introduce a delay between receiving challenge and sending response
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    wr.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr.write_all(b"NICK expired\r\n").await.unwrap();
    wr.write_all(b"USER expired 0 * :Expired\r\n").await.unwrap();

    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") { break; }
    }

    wr.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("ACK") { break; }
    }

    wr.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") { break; }
    }

    let challenge_b64 = line.trim().strip_prefix("AUTHENTICATE ").unwrap().to_string();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge_b64).unwrap();

    // Wait for the challenge to expire (1s timeout, need > 1s with whole-second timestamps)
    tokio::time::sleep(Duration::from_millis(2100)).await;

    // Now sign and send the response
    let signature = private_key.sign(&challenge_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let response = serde_json::json!({
        "did": did_str,
        "method": "crypto",
        "signature": sig_b64,
    });
    let response_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&response).unwrap());

    wr.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes()).await.unwrap();

    // Should get 904 (SASL failure) due to expired challenge
    let mut got_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("904") {
                    got_failure = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(got_failure, "Expected 904 SASL failure for expired challenge");

    wr.write_all(b"CAP END\r\n").await.unwrap();

    // Should still complete registration as guest
    let mut got_welcome = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("001") {
                    got_welcome = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(got_welcome, "Expected 001 welcome after failed SASL");

    wr.write_all(b"QUIT\r\n").await.unwrap();
    server_handle.abort();
}

// ── Test: Replayed nonce is rejected ────────────────────────────────

#[tokio::test]
async fn auth_fails_replayed_nonce() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testreplay";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs);

    let (addr, server_handle) = start_test_server(resolver).await;

    // First: do a legitimate auth via raw TCP and capture the response
    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    wr.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr.write_all(b"NICK replaytest\r\n").await.unwrap();
    wr.write_all(b"USER replaytest 0 * :Test\r\n").await.unwrap();

    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") { break; }
    }

    wr.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("ACK") { break; }
    }

    wr.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n").await.unwrap();
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") { break; }
    }

    let challenge_b64 = line.trim().strip_prefix("AUTHENTICATE ").unwrap().to_string();
    let challenge_bytes = URL_SAFE_NO_PAD.decode(&challenge_b64).unwrap();

    let signature = private_key.sign(&challenge_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let response = serde_json::json!({
        "did": did_str,
        "method": "crypto",
        "signature": sig_b64,
    });
    let response_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&response).unwrap());

    wr.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes()).await.unwrap();

    // Read until 903 (success)
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line.contains("903") { break; }
    }

    wr.write_all(b"CAP END\r\nQUIT\r\n").await.unwrap();
    drop(wr);

    // Brief pause to let server clean up
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection: try to replay the same SASL response
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let (rd2, mut wr2) = stream2.into_split();
    let mut reader2 = BufReader::new(rd2);

    wr2.write_all(b"CAP LS 302\r\n").await.unwrap();
    wr2.write_all(b"NICK replaytest2\r\n").await.unwrap();
    wr2.write_all(b"USER replaytest2 0 * :Test\r\n").await.unwrap();

    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.contains("sasl") || line.contains("SASL") { break; }
    }

    wr2.write_all(b"CAP REQ :sasl\r\n").await.unwrap();
    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.contains("ACK") { break; }
    }

    wr2.write_all(b"AUTHENTICATE ATPROTO-CHALLENGE\r\n").await.unwrap();
    // Get the NEW challenge (different nonce)
    loop {
        line.clear();
        reader2.read_line(&mut line).await.unwrap();
        if line.starts_with("AUTHENTICATE ") && !line.contains("+") { break; }
    }

    // Replay the OLD response (signed over old challenge bytes, not this new one)
    wr2.write_all(format!("AUTHENTICATE {response_b64}\r\n").as_bytes()).await.unwrap();

    // Should get 904 (SASL failure) — signature doesn't match new challenge
    let mut got_failure = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        line.clear();
        let result = tokio::time::timeout_at(deadline, reader2.read_line(&mut line)).await;
        match result {
            Ok(Ok(_)) => {
                if line.contains("904") {
                    got_failure = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(got_failure, "Expected 904 SASL failure for replayed nonce");

    wr2.write_all(b"QUIT\r\n").await.unwrap();
    server_handle.abort();
}

// ── Test: Channel key (+k) ──────────────────────────────────────────

#[tokio::test]
async fn channel_key() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice creates a channel and sets a key
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#secret").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Set channel key
    handle1.raw("MODE #secret +k hunter2").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob tries to join without key — should fail
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#secret").await.unwrap();

    // Bob should get a RawLine with 475 (ERR_BADCHANNELKEY)
    expect_event(&mut events2, 2000, |e| {
        matches!(e, Event::RawLine(line) if line.contains("475"))
    }, "Bob gets 475 ERR_BADCHANNELKEY").await;

    // Bob tries again with the correct key
    handle2.raw("JOIN #secret hunter2").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { channel, nick } if channel == "#secret" && nick == "bob"), "Bob joined with key").await;

    // Alice removes the key
    handle1.raw("MODE #secret -k").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Carol can join without a key now
    let config3 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "carol".to_string(),
        user: "carol".to_string(),
        realname: "Carol".to_string(),
        ..Default::default()
    };
    let (handle3, mut events3) = client::connect(config3, None);
    expect_event(&mut events3, 2000, |e| matches!(e, Event::Registered { .. }), "Carol registered").await;
    handle3.join("#secret").await.unwrap();
    expect_event(&mut events3, 2000, |e| matches!(e, Event::Joined { channel, nick } if channel == "#secret" && nick == "carol"), "Carol joined").await;

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    handle3.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: TLS connection ────────────────────────────────────────────

#[tokio::test]
async fn tls_connection() {
    use std::io::Write;

    // Ensure a crypto provider is installed (iroh may bring ring)
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    // Generate self-signed cert using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    // Write to temp files
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::File::create(&cert_path).unwrap().write_all(cert_pem.as_bytes()).unwrap();
    std::fs::File::create(&key_path).unwrap().write_all(key_pem.as_bytes()).unwrap();

    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        tls_listen_addr: "127.0.0.1:0".to_string(),
        tls_cert: Some(cert_path.to_str().unwrap().to_string()),
        tls_key: Some(key_path.to_str().unwrap().to_string()),
        server_name: "test-tls".to_string(),
        challenge_timeout_secs: 60,
        db_path: None,
        web_addr: None,
        iroh: false,
        iroh_port: None,
        s2s_peers: vec![],
    };

    let server = freeq_server::server::Server::with_resolver(config, empty_resolver());
    let (addr, tls_addr, server_handle) = server.start_tls().await.unwrap();

    // Connect via TLS using the SDK
    let tls_config = ConnectConfig {
        server_addr: tls_addr.to_string(),
        nick: "tlsuser".to_string(),
        user: "tlsuser".to_string(),
        realname: "TLS User".to_string(),
        tls: true,
        tls_insecure: true, // Self-signed cert
    };

    let (handle, mut events) = client::connect(tls_config, None);

    expect_event(&mut events, 3000, |e| matches!(e, Event::Connected), "Connected via TLS").await;
    expect_event(&mut events, 3000, |e| matches!(e, Event::Registered { .. }), "Registered via TLS").await;

    // Also verify the plain port still works
    let plain_config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "plainuser".to_string(),
        user: "plainuser".to_string(),
        realname: "Plain User".to_string(),
        ..Default::default()
    };

    let (handle2, mut events2) = client::connect(plain_config, None);
    expect_event(&mut events2, 3000, |e| matches!(e, Event::Connected), "Connected via plain").await;
    expect_event(&mut events2, 3000, |e| matches!(e, Event::Registered { .. }), "Registered via plain").await;

    handle.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Test: Rich media tags passthrough ───────────────────────────────

#[tokio::test]
async fn media_tags_passthrough() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    // Alice connects
    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#media").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    // Bob connects
    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#media").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Drain bob's join from alice's stream
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"), "Alice sees bob").await;

    // Alice sends a media message with tags
    let media = freeq_sdk::media::MediaAttachment {
        content_type: "image/jpeg".to_string(),
        url: "https://cdn.example.com/photo.jpg".to_string(),
        alt: Some("A sunset".to_string()),
        width: Some(1200),
        height: Some(800),
        blurhash: None,
        size: Some(45000),
        filename: None,
    };
    handle1.send_media("#media", &media).await.unwrap();

    // Bob should receive the message with tags
    let msg = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::Message { from, target, .. } if from == "alice" && target == "#media"),
        "Bob receives media message",
    ).await;

    if let Event::Message { tags, text, .. } = msg {
        // Tags should be present (both clients negotiated message-tags)
        assert_eq!(tags.get("content-type").map(|s| s.as_str()), Some("image/jpeg"));
        assert_eq!(tags.get("media-url").map(|s| s.as_str()), Some("https://cdn.example.com/photo.jpg"));
        assert_eq!(tags.get("media-alt").map(|s| s.as_str()), Some("A sunset"));
        assert_eq!(tags.get("media-w").map(|s| s.as_str()), Some("1200"));
        // Fallback text should contain the URL
        assert!(text.contains("https://cdn.example.com/photo.jpg"));
    } else {
        panic!("Expected Message event");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn tagmsg_and_reactions() {
    let (addr, server_handle) = start_test_server(empty_resolver()).await;

    let config1 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "alice".to_string(),
        user: "alice".to_string(),
        realname: "Alice".to_string(),
        ..Default::default()
    };
    let (handle1, mut events1) = client::connect(config1, None);
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Registered { .. }), "Alice registered").await;
    handle1.join("#react").await.unwrap();
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { .. }), "Alice joined").await;

    let config2 = ConnectConfig {
        server_addr: addr.to_string(),
        nick: "bob".to_string(),
        user: "bob".to_string(),
        realname: "Bob".to_string(),
        ..Default::default()
    };
    let (handle2, mut events2) = client::connect(config2, None);
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Registered { .. }), "Bob registered").await;
    handle2.join("#react").await.unwrap();
    expect_event(&mut events2, 2000, |e| matches!(e, Event::Joined { .. }), "Bob joined").await;

    // Drain bob's join from alice
    expect_event(&mut events1, 2000, |e| matches!(e, Event::Joined { nick, .. } if nick == "bob"), "Alice sees bob").await;

    // Alice sends a reaction via TAGMSG
    let reaction = freeq_sdk::media::Reaction {
        emoji: "🔥".to_string(),
        msgid: None,
    };
    handle1.send_tagmsg("#react", reaction.to_tags()).await.unwrap();

    // Bob should receive the TAGMSG with reaction tags
    let msg = expect_event(
        &mut events2, 2000,
        |e| matches!(e, Event::TagMsg { from, target, .. } if from == "alice" && target == "#react"),
        "Bob receives TAGMSG",
    ).await;

    if let Event::TagMsg { tags, .. } = msg {
        let parsed = freeq_sdk::media::Reaction::from_tags(&tags).unwrap();
        assert_eq!(parsed.emoji, "🔥");
    } else {
        panic!("Expected TagMsg event");
    }

    handle1.quit(None).await.unwrap();
    handle2.quit(None).await.unwrap();
    server_handle.abort();
}

// ── Persistence tests ───────────────────────────────────────────────

/// Helper: start a server with persistence enabled (SQLite file).
async fn start_test_server_with_db(
    resolver: DidResolver,
    db_path: &str,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-server".to_string(),
        challenge_timeout_secs: 60,
        db_path: Some(db_path.to_string()),
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start().await.unwrap()
}

#[tokio::test]
async fn persistence_messages_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First server instance: send a message
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "alice".to_string(),
            user: "alice".to_string(),
            realname: "Alice".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 2000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.join("#persist").await.unwrap();
        expect_event(&mut events, 2000, |e| matches!(e, Event::Joined { channel, .. } if channel == "#persist"), "Joined").await;

        handle.privmsg("#persist", "hello from first server").await.unwrap();
        // Give time for the message to be stored
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second server instance: join channel, should see history
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "bob".to_string(),
            user: "bob".to_string(),
            realname: "Bob".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 2000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.join("#persist").await.unwrap();
        expect_event(&mut events, 2000, |e| matches!(e, Event::Joined { channel, .. } if channel == "#persist"), "Joined").await;

        // Should receive the replayed message from the first server instance
        let msg = expect_event(
            &mut events, 2000,
            |e| matches!(e, Event::Message { text, .. } if text == "hello from first server"),
            "History replay from persisted DB",
        ).await;

        if let Event::Message { from, target, text, .. } = msg {
            assert!(from.contains("alice"), "Message should be from alice, got: {from}");
            assert_eq!(target, "#persist");
            assert_eq!(text, "hello from first server");
        }

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}

#[tokio::test]
async fn persistence_topic_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First instance: set a topic
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "alice".to_string(),
            user: "alice".to_string(),
            realname: "Alice".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 2000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.join("#topictest").await.unwrap();
        expect_event(&mut events, 2000, |e| matches!(e, Event::Joined { channel, .. } if channel == "#topictest"), "Joined").await;

        handle.raw("TOPIC #topictest :Persistent topic!").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second instance: join, should see persisted topic
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "bob".to_string(),
            user: "bob".to_string(),
            realname: "Bob".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 2000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.join("#topictest").await.unwrap();
        expect_event(&mut events, 2000, |e| matches!(e, Event::Joined { channel, .. } if channel == "#topictest"), "Joined").await;

        // Should receive the topic on join
        let _topic = expect_event(
            &mut events, 2000,
            |e| matches!(e, Event::TopicChanged { channel, topic, .. } if channel == "#topictest" && topic == "Persistent topic!"),
            "Persisted topic on join",
        ).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}

#[tokio::test]
async fn persistence_bans_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    // First instance: set a ban
    {
        let (addr, server_handle) = start_test_server_with_db(empty_resolver(), db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "op".to_string(),
            user: "op".to_string(),
            realname: "Op".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 2000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.join("#btest").await.unwrap();
        expect_event(&mut events, 2000, |e| matches!(e, Event::Joined { channel, .. } if channel == "#btest"), "Joined").await;

        // As channel creator, we're op — set a ban
        handle.raw("MODE #btest +b bad!*@*").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify the ban is in the database directly
    {
        let db = freeq_server::db::Db::open(db_str).unwrap();
        let channels = db.load_channels().unwrap();
        let ch = channels.get("#btest").unwrap();
        assert_eq!(ch.bans.len(), 1);
        assert_eq!(ch.bans[0].mask, "bad!*@*");
    }
}


#[tokio::test]
async fn persistence_nick_ownership_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db_str = db_path.to_str().unwrap();

    let private_key = PrivateKey::generate_secp256k1();
    let did_str = "did:plc:testpersist";
    let doc = did::make_test_did_document(did_str, &private_key.public_key_multibase());

    let mut docs = HashMap::new();
    docs.insert(did_str.to_string(), doc);
    let resolver = DidResolver::static_map(docs.clone());

    // First instance: authenticate and claim nick
    {
        let (addr, server_handle) = start_test_server_with_db(resolver, db_str).await;

        let signer: Arc<dyn ChallengeSigner> = Arc::new(KeySigner::new(did_str.to_string(), private_key));
        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "claimed".to_string(),
            user: "claimed".to_string(),
            realname: "Claimed".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, Some(signer));
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;
        expect_event(&mut events, 3000, |e| matches!(e, Event::Registered { .. }), "Registered").await;

        handle.quit(None).await.unwrap();
        server_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second instance: guest tries to use claimed nick — should be renamed
    {
        let resolver2 = DidResolver::static_map(docs);
        let (addr, server_handle) = start_test_server_with_db(resolver2, db_str).await;

        let config = ConnectConfig {
            server_addr: addr.to_string(),
            nick: "claimed".to_string(),
            user: "claimed".to_string(),
            realname: "Guest".to_string(),
            ..Default::default()
        };
        let (handle, mut events) = client::connect(config, None);
        expect_event(&mut events, 2000, |e| matches!(e, Event::Connected), "Connected").await;

        // The registered event should show a different nick (Guest*)
        let reg = expect_event(
            &mut events, 2000,
            |e| matches!(e, Event::Registered { .. }),
            "Registered",
        ).await;

        if let Event::Registered { nick, .. } = reg {
            assert!(nick.starts_with("Guest"), "Guest should be renamed, got: {nick}");
        }

        handle.quit(None).await.unwrap();
        server_handle.abort();
    }
}
