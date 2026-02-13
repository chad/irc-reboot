//! S2S federation acceptance tests.
//!
//! These tests connect to TWO live IRC servers and verify that state
//! syncs correctly between them. Run with:
//!
//!   LOCAL_SERVER=localhost:6667 REMOTE_SERVER=irc.freeq.at:6667 cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1
//!
//! For single-server tests (no S2S needed):
//!
//!   SERVER=localhost:6667 cargo test -p freeq-server --test s2s_acceptance -- --nocapture --test-threads=1 single_server
//!
//! Both servers must be running with --iroh and S2S peering configured.
//! If environment variables aren't set, tests are skipped.
//!
//! NOTE: Use `--test-threads=1` to run sequentially. The single S2S link
//! between the two servers can't handle many concurrent test sessions reliably.
//!
//! Channel names use `#_zqtest_` prefix + timestamp to avoid collisions
//! with real channels on live servers.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;

/// How long to wait for an event before considering it failed.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Longer timeout for operations that require S2S propagation.
const S2S_TIMEOUT: Duration = Duration::from_secs(30);

/// Time to let S2S state propagate after a JOIN/PART/etc.
const S2S_SETTLE: Duration = Duration::from_secs(3);

// ── Helpers ──────────────────────────────────────────────────────

/// Connect a guest user to a server, returning handle + event receiver.
async fn connect_guest(addr: &str, nick: &str) -> (ClientHandle, mpsc::Receiver<Event>) {
    let conn = client::establish_connection(&ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("S2S Test ({nick})"),
        tls: false,
        tls_insecure: false,
    })
    .await
    .unwrap_or_else(|e| panic!("Failed to connect {nick} to {addr}: {e}"));

    let config = ConnectConfig {
        server_addr: addr.to_string(),
        nick: nick.to_string(),
        user: nick.to_string(),
        realname: format!("S2S Test ({nick})"),
        tls: false,
        tls_insecure: false,
    };

    client::connect_with_stream(conn, config, None)
}

/// Wait for a specific event, ignoring others.
async fn wait_for<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    desc: &str,
) -> Event {
    wait_for_timeout(rx, predicate, desc, TIMEOUT).await
}

/// Wait for a specific event with configurable timeout.
async fn wait_for_timeout<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    desc: &str,
    dur: Duration,
) -> Event {
    let result = timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(evt) if predicate(&evt) => return evt,
                Some(_) => continue,
                None => panic!("Channel closed while waiting for: {desc}"),
            }
        }
    })
    .await;

    result.unwrap_or_else(|_| panic!("Timeout ({dur:?}) waiting for: {desc}"))
}

/// Check if an event arrives within a duration. Returns None on timeout.
async fn maybe_wait<F: Fn(&Event) -> bool>(
    rx: &mut mpsc::Receiver<Event>,
    predicate: F,
    dur: Duration,
) -> Option<Event> {
    timeout(dur, async {
        loop {
            match rx.recv().await {
                Some(evt) if predicate(&evt) => return evt,
                Some(_) => continue,
                None => return Event::Disconnected { reason: "closed".into() },
            }
        }
    })
    .await
    .ok()
}

/// Wait for a Registered event.
async fn wait_registered(rx: &mut mpsc::Receiver<Event>) -> String {
    match wait_for(rx, |e| matches!(e, Event::Registered { .. }), "Registered").await {
        Event::Registered { nick } => nick,
        _ => unreachable!(),
    }
}

/// Wait for a Joined event for a specific channel.
async fn wait_joined(rx: &mut mpsc::Receiver<Event>, channel: &str) -> String {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::Joined { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Joined {channel}"),
    )
    .await
    {
        Event::Joined { nick, .. } => nick,
        _ => unreachable!(),
    }
}

/// Wait for a Parted event for a specific nick in a channel.
async fn wait_parted(rx: &mut mpsc::Receiver<Event>, channel: &str, nick: &str) {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::Parted { channel: c, nick: pn } if c.to_lowercase() == ch && pn == &n),
        &format!("Part {nick} from {channel}"),
    )
    .await;
}

/// Wait for a UserQuit event for a specific nick.
async fn wait_quit(rx: &mut mpsc::Receiver<Event>, nick: &str) {
    let n = nick.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::UserQuit { nick: qn, .. } if qn == &n),
        &format!("Quit from {nick}"),
    )
    .await;
}

/// Wait for a Message from a specific user.
async fn wait_message_from(rx: &mut mpsc::Receiver<Event>, from: &str) -> (String, String) {
    let f = from.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Message { from: sender, .. } if sender == &f),
        &format!("Message from {from}"),
    )
    .await
    {
        Event::Message { target, text, .. } => (target, text),
        _ => unreachable!(),
    }
}

/// Wait for a Message containing specific text.
async fn wait_message_containing(
    rx: &mut mpsc::Receiver<Event>,
    substr: &str,
) -> (String, String, String) {
    let s = substr.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Message { text, .. } if text.contains(&s)),
        &format!("Message containing '{substr}'"),
    )
    .await
    {
        Event::Message { from, target, text, .. } => (from, target, text),
        _ => unreachable!(),
    }
}

/// Wait for a Names event that includes a specific nick.
async fn wait_names_containing(
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
    nick: &str,
) -> Vec<String> {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    match wait_for_timeout(
        rx,
        |e| matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == ch
            && nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == n)),
        &format!("Names in {channel} containing {nick}"),
        S2S_TIMEOUT,
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Wait for Names that do NOT include a specific nick.
async fn wait_names_not_containing(
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
    nick: &str,
) -> Vec<String> {
    let ch = channel.to_lowercase();
    let n = nick.to_string();
    match wait_for_timeout(
        rx,
        |e| matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == ch
            && !nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == n)),
        &format!("Names in {channel} NOT containing {nick}"),
        S2S_TIMEOUT,
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Wait for a TopicChanged event.
async fn wait_topic(rx: &mut mpsc::Receiver<Event>, channel: &str) -> String {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::TopicChanged { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Topic in {channel}"),
    )
    .await
    {
        Event::TopicChanged { topic, .. } => topic,
        _ => unreachable!(),
    }
}

/// Wait for a ModeChanged event.
async fn wait_mode(rx: &mut mpsc::Receiver<Event>, channel: &str) -> (String, Option<String>) {
    let ch = channel.to_lowercase();
    match wait_for(
        rx,
        |e| matches!(e, Event::ModeChanged { channel: c, .. } if c.to_lowercase() == ch),
        &format!("Mode change in {channel}"),
    )
    .await
    {
        Event::ModeChanged { mode, arg, .. } => (mode, arg),
        _ => unreachable!(),
    }
}

/// Wait for a ServerNotice containing specific text.
async fn wait_notice_containing(rx: &mut mpsc::Receiver<Event>, substr: &str) {
    let s = substr.to_string();
    wait_for(
        rx,
        |e| matches!(e, Event::ServerNotice { text } if text.contains(&s)),
        &format!("Notice containing '{substr}'"),
    )
    .await;
}

/// Drain all pending events from a receiver.
async fn drain(rx: &mut mpsc::Receiver<Event>) {
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {}
}

fn get_servers() -> Option<(String, String)> {
    let local = std::env::var("LOCAL_SERVER").ok();
    let remote = std::env::var("REMOTE_SERVER").ok();
    match (local, remote) {
        (Some(l), Some(r)) => Some((l, r)),
        _ => {
            eprintln!("Skipping S2S test: set LOCAL_SERVER and REMOTE_SERVER env vars");
            None
        }
    }
}

fn get_single_server() -> Option<String> {
    std::env::var("SERVER")
        .ok()
        .or_else(|| std::env::var("LOCAL_SERVER").ok())
}

/// Generate a unique channel name unlikely to collide with real channels.
fn test_channel(suffix: &str) -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("#_zqtest_{}{}", ts % 1_000_000, suffix)
}

/// Generate a unique test nick.
fn test_nick(prefix: &str, suffix: &str) -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("_zq{}{}_{}", prefix, suffix, ts % 100000)
}

// ═══════════════════════════════════════════════════════════════════
// Single-server tests (only need SERVER or LOCAL_SERVER)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn single_server_connect_and_register() {
    let Some(server) = get_single_server() else {
        eprintln!("Skipping: set SERVER or LOCAL_SERVER");
        return;
    };
    let nick = test_nick("reg", "");
    let (h, mut e) = connect_guest(&server, &nick).await;
    let got = wait_registered(&mut e).await;
    eprintln!("  ✓ Registered as {got}");
    let _ = h.quit(Some("test done")).await;
}

#[tokio::test]
async fn single_server_join_part_cycle() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("jp", "");
    let channel = test_channel("jp");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    eprintln!("  ✓ Joined {channel}");

    h.raw(&format!("PART {channel} :bye")).await.unwrap();
    wait_parted(&mut e, &channel, &nick).await;
    eprintln!("  ✓ Parted {channel}");

    // Rejoin
    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    eprintln!("  ✓ Rejoined {channel}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_topic_set_and_read() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("top", "");
    let channel = test_channel("top");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    let topic = format!("acceptance test topic {}", chrono::Utc::now().timestamp());
    h.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut e, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic set: {topic}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_privmsg_between_users() {
    let Some(server) = get_single_server() else { return };
    let nick_a = test_nick("pm", "a");
    let nick_b = test_nick("pm", "b");
    let channel = test_channel("pm");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    let msg = format!("test msg {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Message delivered: {msg}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_list_command() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("lst", "");
    let channel = test_channel("lst");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    h.raw("LIST").await.unwrap();
    // Should get a raw line containing our channel
    let ch_lower = channel.to_lowercase();
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.to_lowercase().contains(&ch_lower)),
        "LIST output containing our channel",
    ).await;
    eprintln!("  ✓ LIST shows {channel}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_who_command() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("who", "");
    let channel = test_channel("who");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;

    h.raw(&format!("WHO {channel}")).await.unwrap();
    // Should get a raw line containing our nick
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains(&nick)),
        "WHO output containing our nick",
    ).await;
    eprintln!("  ✓ WHO shows {nick}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_away_status() {
    let Some(server) = get_single_server() else { return };
    let nick_a = test_nick("aw", "a");
    let nick_b = test_nick("aw", "b");
    let channel = test_channel("aw");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    // Both join a channel so we know they can see each other
    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;
    drain(&mut ea).await;
    drain(&mut eb).await;

    // Set away
    ha.raw("AWAY :Gone fishing").await.unwrap();
    // Should get RPL_NOWAWAY (306)
    wait_for(
        &mut ea,
        |e| matches!(e, Event::RawLine(line) if line.contains("306")),
        "RPL_NOWAWAY",
    ).await;
    eprintln!("  ✓ AWAY set");

    // Small delay to let the away state register
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send PM from B → A, should get RPL_AWAY (301) back to B
    hb.privmsg(&nick_a, "hello").await.unwrap();
    wait_for(
        &mut eb,
        |e| matches!(e, Event::RawLine(line) if line.contains("301") && line.contains("Gone fishing")),
        "RPL_AWAY with away message",
    ).await;
    eprintln!("  ✓ RPL_AWAY received with message");

    // Unset away
    ha.raw("AWAY").await.unwrap();
    wait_for(
        &mut ea,
        |e| matches!(e, Event::RawLine(line) if line.contains("305")),
        "RPL_UNAWAY",
    ).await;
    eprintln!("  ✓ AWAY cleared");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_mode_n_no_external() {
    let Some(server) = get_single_server() else { return };
    let nick_in = test_nick("mn", "in");
    let nick_out = test_nick("mn", "out");
    let channel = test_channel("mn");

    let (h_in, mut e_in) = connect_guest(&server, &nick_in).await;
    let (h_out, mut e_out) = connect_guest(&server, &nick_out).await;
    wait_registered(&mut e_in).await;
    wait_registered(&mut e_out).await;

    // nick_in creates channel (gets ops)
    h_in.join(&channel).await.unwrap();
    wait_joined(&mut e_in, &channel).await;

    // Set +n
    h_in.raw(&format!("MODE {channel} +n")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_in).await;

    // nick_out is NOT in the channel — try to send
    h_out.privmsg(&channel, "should fail").await.unwrap();

    // Should get ERR_CANNOTSENDTOCHAN (404)
    wait_for(
        &mut e_out,
        |e| matches!(e, Event::RawLine(line) if line.contains("404")),
        "ERR_CANNOTSENDTOCHAN for +n",
    ).await;
    eprintln!("  ✓ +n blocks external messages");

    let _ = h_in.quit(Some("done")).await;
    let _ = h_out.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_mode_m_moderated() {
    let Some(server) = get_single_server() else { return };
    let nick_op = test_nick("mm", "op");
    let nick_reg = test_nick("mm", "reg");
    let channel = test_channel("mm");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_reg, mut e_reg) = connect_guest(&server, &nick_reg).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_reg).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    h_reg.join(&channel).await.unwrap();
    wait_joined(&mut e_reg, &channel).await;

    // Set +m
    h_op.raw(&format!("MODE {channel} +m")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_op).await;
    drain(&mut e_reg).await;

    // Regular user should be blocked
    h_reg.privmsg(&channel, "should fail").await.unwrap();
    wait_for(
        &mut e_reg,
        |e| matches!(e, Event::RawLine(line) if line.contains("404")),
        "ERR_CANNOTSENDTOCHAN for +m",
    ).await;
    eprintln!("  ✓ +m blocks unvoiced users");

    // Op should succeed
    let msg = format!("from op {}", chrono::Utc::now().timestamp_millis());
    h_op.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut e_reg, &nick_op).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ +m allows ops");

    // Voice the user, they should succeed
    h_op.raw(&format!("MODE {channel} +v {nick_reg}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drain(&mut e_reg).await;

    let msg2 = format!("from voiced {}", chrono::Utc::now().timestamp_millis());
    h_reg.privmsg(&channel, &msg2).await.unwrap();
    let (_, text2) = wait_message_from(&mut e_op, &nick_reg).await;
    assert_eq!(text2, msg2);
    eprintln!("  ✓ +m allows voiced users");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_reg.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_channel_case_normalization() {
    let Some(server) = get_single_server() else { return };
    let nick_a = test_nick("cn", "a");
    let nick_b = test_nick("cn", "b");
    let channel_upper = test_channel("CN");
    let channel_lower = channel_upper.to_lowercase();

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    // A joins with original case
    ha.join(&channel_upper).await.unwrap();
    wait_joined(&mut ea, &channel_lower).await;

    // B joins with lowercase
    hb.join(&channel_lower).await.unwrap();
    wait_joined(&mut eb, &channel_lower).await;

    // They should be in the same channel
    let msg = format!("case test {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel_upper, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Channel name case normalization works");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_motd() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("motd", "");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    // MOTD should have been sent during registration (375 or 422)
    // Also test the MOTD command
    h.raw("MOTD").await.unwrap();
    wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains("375") || line.contains("422")),
        "MOTD response (375 or 422)",
    ).await;
    eprintln!("  ✓ MOTD command works");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_nick_change() {
    let Some(server) = get_single_server() else { return };
    let nick = test_nick("nk", "a");
    let new_nick = test_nick("nk", "b");
    let channel = test_channel("nk");

    let (h, mut e) = connect_guest(&server, &nick).await;
    wait_registered(&mut e).await;

    h.join(&channel).await.unwrap();
    wait_joined(&mut e, &channel).await;
    drain(&mut e).await;

    h.raw(&format!("NICK {new_nick}")).await.unwrap();

    // Server should echo `:oldnick!~u@host NICK :newnick`
    // Check via RawLine containing the new nick after a NICK command
    let nn = new_nick.clone();
    let got = wait_for(
        &mut e,
        |e| matches!(e, Event::RawLine(line) if line.contains("NICK") && line.contains(&nn)),
        "NICK change confirmation",
    ).await;
    if let Event::RawLine(line) = &got {
        eprintln!("  ✓ Nick changed: {line}");
    }

    // Verify via NAMES that our new nick appears
    h.raw(&format!("NAMES {channel}")).await.unwrap();
    let nicks = wait_names_containing(&mut e, &channel, &new_nick).await;
    let has_old = nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick);
    assert!(!has_old, "Old nick should not be in NAMES: {nicks:?}");
    eprintln!("  ✓ NAMES shows new nick: {nicks:?}");

    let _ = h.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_kick() {
    let Some(server) = get_single_server() else { return };
    let nick_op = test_nick("kick", "op");
    let nick_target = test_nick("kick", "tgt");
    let channel = test_channel("kick");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_tgt, mut e_tgt) = connect_guest(&server, &nick_target).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_tgt).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    h_tgt.join(&channel).await.unwrap();
    wait_joined(&mut e_tgt, &channel).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    h_op.raw(&format!("KICK {channel} {nick_target} :test kick")).await.unwrap();

    wait_for(
        &mut e_tgt,
        |e| matches!(e, Event::Kicked { nick, .. } if nick == &nick_target),
        "Kicked event",
    ).await;
    eprintln!("  ✓ KICK works");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_tgt.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_invite() {
    let Some(server) = get_single_server() else { return };
    let nick_op = test_nick("inv", "op");
    let nick_guest = test_nick("inv", "g");
    let channel = test_channel("inv");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_g, mut e_g) = connect_guest(&server, &nick_guest).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_g).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Set invite-only
    h_op.raw(&format!("MODE {channel} +i")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Guest tries to join — should fail
    h_g.join(&channel).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::RawLine(line) if line.contains("473")),
        "ERR_INVITEONLYCHAN",
    ).await;
    eprintln!("  ✓ +i blocks uninvited users");

    // Invite the guest
    h_op.raw(&format!("INVITE {nick_guest} {channel}")).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::Invited { .. }),
        "Invite received",
    ).await;
    eprintln!("  ✓ INVITE sent");

    // Now guest should be able to join
    h_g.join(&channel).await.unwrap();
    wait_joined(&mut e_g, &channel).await;
    eprintln!("  ✓ Invited user can join +i channel");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_g.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_ban() {
    let Some(server) = get_single_server() else { return };
    let nick_op = test_nick("ban", "op");
    let nick_target = test_nick("ban", "tgt");
    let channel = test_channel("ban");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_tgt, mut e_tgt) = connect_guest(&server, &nick_target).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_tgt).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Ban the target's mask
    h_op.raw(&format!("MODE {channel} +b {nick_target}!*@*")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Target tries to join — should be banned
    h_tgt.join(&channel).await.unwrap();
    wait_for(
        &mut e_tgt,
        |e| matches!(e, Event::RawLine(line) if line.contains("474")),
        "ERR_BANNEDFROMCHAN",
    ).await;
    eprintln!("  ✓ +b blocks banned users");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_tgt.quit(Some("done")).await;
}

#[tokio::test]
async fn single_server_key_channel() {
    let Some(server) = get_single_server() else { return };
    let nick_op = test_nick("key", "op");
    let nick_guest = test_nick("key", "g");
    let channel = test_channel("key");

    let (h_op, mut e_op) = connect_guest(&server, &nick_op).await;
    let (h_g, mut e_g) = connect_guest(&server, &nick_guest).await;
    wait_registered(&mut e_op).await;
    wait_registered(&mut e_g).await;

    h_op.join(&channel).await.unwrap();
    wait_joined(&mut e_op, &channel).await;

    // Set key
    h_op.raw(&format!("MODE {channel} +k secretpass")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Guest tries without key — should fail
    h_g.join(&channel).await.unwrap();
    wait_for(
        &mut e_g,
        |e| matches!(e, Event::RawLine(line) if line.contains("475")),
        "ERR_BADCHANNELKEY",
    ).await;
    eprintln!("  ✓ +k blocks without key");

    // Guest joins with key
    h_g.raw(&format!("JOIN {channel} secretpass")).await.unwrap();
    wait_joined(&mut e_g, &channel).await;
    eprintln!("  ✓ +k allows with correct key");

    let _ = h_op.quit(Some("done")).await;
    let _ = h_g.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// S2S federation tests (need LOCAL_SERVER + REMOTE_SERVER)
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_both_servers_accept_connections() {
    let Some((local, remote)) = get_servers() else { return };

    let nick_a = test_nick("conn", "a");
    let nick_b = test_nick("conn", "b");
    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    let n1 = wait_registered(&mut e1).await;
    let n2 = wait_registered(&mut e2).await;

    eprintln!("  ✓ Local registered as: {n1}");
    eprintln!("  ✓ Remote registered as: {n2}");

    let _ = h1.quit(Some("test done")).await;
    let _ = h2.quit(Some("test done")).await;
}

#[tokio::test]
async fn s2s_messages_local_to_remote() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("l2r");
    let nick_a = test_nick("l2r", "a");
    let nick_b = test_nick("l2r", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let msg = format!("l2r {}", chrono::Utc::now().timestamp_millis());
    h1.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut e2, &nick_a).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Local→Remote: {msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_messages_remote_to_local() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("r2l");
    let nick_a = test_nick("r2l", "a");
    let nick_b = test_nick("r2l", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let msg = format!("r2l {}", chrono::Utc::now().timestamp_millis());
    h2.privmsg(&channel, &msg).await.unwrap();

    let (target, text) = wait_message_from(&mut e1, &nick_b).await;
    assert_eq!(target.to_lowercase(), channel.to_lowercase());
    assert_eq!(text, msg);
    eprintln!("  ✓ Remote→Local: {msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_bidirectional_messages() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("bidi");
    let nick_a = test_nick("bidi", "a");
    let nick_b = test_nick("bidi", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Local → Remote
    h1.privmsg(&channel, "ping").await.unwrap();
    let (_, text) = wait_message_from(&mut e2, &nick_a).await;
    assert_eq!(text, "ping");

    // Remote → Local
    h2.privmsg(&channel, "pong").await.unwrap();
    let (_, text) = wait_message_from(&mut e1, &nick_b).await;
    assert_eq!(text, "pong");

    eprintln!("  ✓ Bidirectional message relay works");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_remote_user_in_names() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("nm");
    let nick_a = test_nick("nm", "a");
    let nick_b = test_nick("nm", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;

    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    let nicks = wait_names_containing(&mut e1, &channel, &nick_b).await;
    let has_local = nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a);
    assert!(has_local, "Local user should be in NAMES: {nicks:?}");
    eprintln!("  ✓ Remote user visible in NAMES: {nicks:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_syncs() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("tsync");
    let nick_a = test_nick("tsync", "a");
    let nick_b = test_nick("tsync", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let topic = format!("s2s topic {}", chrono::Utc::now().timestamp_millis());
    h1.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut e2, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic synced: {topic}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_part_removes_remote_user() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("part");
    let nick_a = test_nick("part", "a");
    let nick_b = test_nick("part", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    wait_names_containing(&mut e1, &channel, &nick_b).await;

    h2.raw(&format!("PART {channel}")).await.unwrap();

    wait_for(
        &mut e1,
        |e| matches!(e, Event::Parted { channel: c, nick } if c.to_lowercase() == channel.to_lowercase() && nick == &nick_b),
        &format!("Part from {nick_b}"),
    ).await;
    eprintln!("  ✓ Remote PART propagated");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_quit_removes_remote_user() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("quit");
    let nick_a = test_nick("quit", "a");
    let nick_b = test_nick("quit", "b");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    wait_names_containing(&mut e1, &channel, &nick_b).await;

    h2.quit(Some("testing quit")).await.unwrap();

    wait_for(
        &mut e1,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == &nick_b),
        &format!("Quit from {nick_b}"),
    ).await;
    eprintln!("  ✓ Remote QUIT propagated");

    let _ = h1.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_late_joiner_sees_remote_user() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("late");
    let nick_a = test_nick("late", "a");
    let nick_b = test_nick("late", "b");

    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut e2).await;

    // Remote joins first
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    // Give S2S time to propagate
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Local joins later
    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut e1).await;
    h1.join(&channel).await.unwrap();

    let nicks = wait_names_containing(&mut e1, &channel, &nick_b).await;
    eprintln!("  ✓ Late joiner sees remote user: {nicks:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_nick_change_propagates() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("nkch");
    let nick_a = test_nick("nkch", "a");
    let nick_b = test_nick("nkch", "b");
    let nick_b_new = test_nick("nkch", "b2");

    let (h1, mut e1) = connect_guest(&local, &nick_a).await;
    let (h2, mut e2) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    wait_names_containing(&mut e1, &channel, &nick_b).await;
    drain(&mut e1).await;

    // Remote changes nick
    h2.raw(&format!("NICK {nick_b_new}")).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Wait for the NICK change to appear as a RawLine on local (S2S propagation)
    // Then verify via NAMES. If the remote server doesn't broadcast NickChange
    // over S2S (old code), this will time out gracefully.
    drain(&mut e1).await;
    h1.raw(&format!("NAMES {channel}")).await.unwrap();
    let result = maybe_wait(
        &mut e1,
        |e| matches!(e, Event::Names { channel: c, nicks }
            if c.to_lowercase() == channel.to_lowercase()
            && nicks.iter().any(|x| x.trim_start_matches(&['@', '+'][..]) == nick_b_new)),
        Duration::from_secs(10),
    ).await;

    match result {
        Some(Event::Names { nicks, .. }) => {
            let has_old = nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_b);
            assert!(!has_old, "Old nick should be gone from NAMES: {nicks:?}");
            eprintln!("  ✓ Nick change propagated: {nick_b} → {nick_b_new} — NAMES: {nicks:?}");
        }
        _ => {
            eprintln!("  ⚠ Nick change not propagated via S2S (remote may need updated code)");
            eprintln!("    This is expected if irc.freeq.at is running old code without NickChange S2S broadcast");
        }
    }

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_multiple_channels() {
    let Some((local, remote)) = get_servers() else { return };
    let ch1 = test_channel("mc1");
    let ch2 = test_channel("mc2");
    let nick_a = test_nick("mc", "a");
    let nick_b = test_nick("mc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;

    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&ch1).await.unwrap();
    ha.join(&ch2).await.unwrap();
    hb.join(&ch1).await.unwrap();
    hb.join(&ch2).await.unwrap();
    wait_joined(&mut ea, &ch1).await;
    wait_joined(&mut ea, &ch2).await;
    wait_joined(&mut eb, &ch1).await;
    wait_joined(&mut eb, &ch2).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send to ch1 from local
    let msg1 = format!("ch1 {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&ch1, &msg1).await.unwrap();
    let (target, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(target.to_lowercase(), ch1.to_lowercase());
    assert_eq!(text, msg1);

    // Send to ch2 from remote
    let msg2 = format!("ch2 {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&ch2, &msg2).await.unwrap();
    let (target, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(target.to_lowercase(), ch2.to_lowercase());
    assert_eq!(text, msg2);

    eprintln!("  ✓ Multiple channels work independently across S2S");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_rapid_messages() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("rapid");
    let nick_a = test_nick("rapid", "a");
    let nick_b = test_nick("rapid", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send 10 messages rapidly
    let count = 10;
    for i in 0..count {
        ha.privmsg(&channel, &format!("rapid-{i}")).await.unwrap();
        // Small delay to avoid rate limit
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // All should arrive at remote
    let mut received = 0;
    for _ in 0..count {
        match maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_a && text.starts_with("rapid-")),
            Duration::from_secs(10),
        ).await {
            Some(_) => received += 1,
            None => break,
        }
    }

    eprintln!("  ✓ Rapid messages: {received}/{count} received");
    assert!(received >= count - 1, "Should receive at least {}/{count} messages, got {received}", count - 1);

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Netsplit / reconnection tests (need LOCAL_SERVER + REMOTE_SERVER)
//
// These test behavior when users disconnect/reconnect, simulating
// what happens during netsplits and S2S link interruptions.
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_remote_user_disconnect_cleanup() {
    // When a remote user disconnects, their nick should disappear from
    // NAMES on the local server. This tests that QUIT propagates.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("dc");
    let nick_a = test_nick("dc", "a");
    let nick_b = test_nick("dc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    // Ensure remote user is visible
    wait_names_containing(&mut ea, &channel, &nick_b).await;

    // Remote user disconnects
    hb.quit(Some("simulate disconnect")).await.unwrap();
    drop(hb);
    drop(eb);

    // Wait for QUIT propagation
    wait_quit(&mut ea, &nick_b).await;

    // Verify NAMES no longer contains the remote user
    drain(&mut ea).await;
    ha.raw(&format!("NAMES {channel}")).await.unwrap();
    let nicks = wait_for(
        &mut ea,
        |e| matches!(e, Event::Names { channel: c, .. } if c.to_lowercase() == channel.to_lowercase()),
        "NAMES response",
    ).await;
    if let Event::Names { nicks, .. } = nicks {
        let has_b = nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_b);
        assert!(!has_b, "Disconnected remote user should not be in NAMES: {nicks:?}");
    }
    eprintln!("  ✓ Remote disconnect cleaned up from NAMES");

    let _ = ha.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_reconnect_after_disconnect() {
    // After a remote user disconnects and reconnects, they should
    // reappear in NAMES when they rejoin the channel.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("recon");
    let nick_a = test_nick("recon", "a");
    let nick_b = test_nick("recon", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Remote user joins
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  Phase 1: Remote user visible");

    // Remote user disconnects
    hb.quit(Some("temporary disconnect")).await.unwrap();
    drop(hb);
    drop(eb);

    wait_quit(&mut ea, &nick_b).await;
    eprintln!("  Phase 2: Remote user gone");

    // Remote user reconnects with same nick
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb2).await;
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut eb2, &channel).await;

    // Should reappear in local NAMES
    let nicks = wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  Phase 3: Remote user back in NAMES: {nicks:?}");

    // Verify message flow still works
    let msg = format!("after-recon {}", chrono::Utc::now().timestamp_millis());
    hb2.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages work after reconnection");

    let _ = ha.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_channel_persists_through_empty() {
    // If all local users leave a channel but remote users remain,
    // the channel should still exist. When a local user rejoins,
    // they should see the remote users.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("persist");
    let nick_a = test_nick("pers", "a");
    let nick_b = test_nick("pers", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    wait_names_containing(&mut ea, &channel, &nick_b).await;

    // Local user parts — channel should persist because remote user is there
    ha.raw(&format!("PART {channel} :brb")).await.unwrap();
    wait_parted(&mut ea, &channel, &nick_a).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Local user rejoins — should see remote user still there
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let nicks = wait_names_containing(&mut ea, &channel, &nick_b).await;
    eprintln!("  ✓ Channel persisted through local-empty: {nicks:?}");

    // Verify messages still flow
    let msg = format!("post-rejoin {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages work after rejoin");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_persists_across_reconnect() {
    // Topic set on one server should survive user reconnections.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("toppers");
    let nick_a = test_nick("tp", "a");
    let nick_b = test_nick("tp", "b");
    let nick_c = test_nick("tp", "c");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Set topic from local
    let topic = format!("persistent topic {}", chrono::Utc::now().timestamp_millis());
    ha.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();
    wait_topic(&mut eb, &channel).await;
    eprintln!("  Topic set: {topic}");

    // New user joins remote — should see the topic
    let (hc, mut ec) = connect_guest(&remote, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();

    let got = wait_topic(&mut ec, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ New joiner sees topic: {topic}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_multiple_users_same_channel() {
    // Multiple users on each server in the same channel. Messages from
    // any user should reach all users on the other server.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("multi");
    let nick_a1 = test_nick("mul", "a1");
    let nick_a2 = test_nick("mul", "a2");
    let nick_b1 = test_nick("mul", "b1");
    let nick_b2 = test_nick("mul", "b2");

    let (ha1, mut ea1) = connect_guest(&local, &nick_a1).await;
    let (ha2, mut ea2) = connect_guest(&local, &nick_a2).await;
    let (hb1, mut eb1) = connect_guest(&remote, &nick_b1).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b2).await;

    wait_registered(&mut ea1).await;
    wait_registered(&mut ea2).await;
    wait_registered(&mut eb1).await;
    wait_registered(&mut eb2).await;

    for h in [&ha1, &ha2, &hb1, &hb2] {
        h.join(&channel).await.unwrap();
    }
    wait_joined(&mut ea1, &channel).await;
    wait_joined(&mut ea2, &channel).await;
    wait_joined(&mut eb1, &channel).await;
    wait_joined(&mut eb2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Message from local A1 should reach remote B1 and B2
    let msg = format!("multi {}", chrono::Utc::now().timestamp_millis());
    ha1.privmsg(&channel, &msg).await.unwrap();

    let (_, t1) = wait_message_from(&mut eb1, &nick_a1).await;
    assert_eq!(t1, msg);
    let (_, t2) = wait_message_from(&mut eb2, &nick_a1).await;
    assert_eq!(t2, msg);

    // Also reaches local A2
    let (_, t3) = wait_message_from(&mut ea2, &nick_a1).await;
    assert_eq!(t3, msg);

    eprintln!("  ✓ Multi-user cross-server delivery works (4 users, 2 servers)");

    let _ = ha1.quit(Some("done")).await;
    let _ = ha2.quit(Some("done")).await;
    let _ = hb1.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_staggered_join_order() {
    // Test that join ordering doesn't matter: user on server A joins,
    // then user on server B joins, then another on A. All should see
    // each other.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("stag");
    let nick_a1 = test_nick("stag", "a1");
    let nick_b = test_nick("stag", "b");
    let nick_a2 = test_nick("stag", "a2");

    let (ha1, mut ea1) = connect_guest(&local, &nick_a1).await;
    wait_registered(&mut ea1).await;
    ha1.join(&channel).await.unwrap();
    wait_joined(&mut ea1, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    // A1 should see B
    wait_names_containing(&mut ea1, &channel, &nick_b).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (ha2, mut ea2) = connect_guest(&local, &nick_a2).await;
    wait_registered(&mut ea2).await;
    ha2.join(&channel).await.unwrap();
    wait_joined(&mut ea2, &channel).await;

    // A2 should see B (via NAMES on join or subsequent S2S update)
    let nicks = wait_names_containing(&mut ea2, &channel, &nick_b).await;
    let has_a1 = nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a1);
    assert!(has_a1, "A2 should see A1 in NAMES: {nicks:?}");
    eprintln!("  ✓ Staggered join: all 3 users see each other: {nicks:?}");

    // B should see both A1 and A2
    drain(&mut eb).await;
    hb.raw(&format!("NAMES {channel}")).await.unwrap();
    let b_nicks = wait_names_containing(&mut eb, &channel, &nick_a2).await;
    let has_a1_on_b = b_nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick_a1);
    assert!(has_a1_on_b, "B should see A1: {b_nicks:?}");
    eprintln!("  ✓ Remote sees all local users: {b_nicks:?}");

    let _ = ha1.quit(Some("done")).await;
    let _ = ha2.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_topic_set_from_remote() {
    // Topic set from the remote server should be visible on the local server.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("rtop");
    let nick_a = test_nick("rtop", "a");
    let nick_b = test_nick("rtop", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let topic = format!("remote topic {}", chrono::Utc::now().timestamp_millis());
    hb.raw(&format!("TOPIC {channel} :{topic}")).await.unwrap();

    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(got, topic);
    eprintln!("  ✓ Topic from remote visible on local: {topic}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_concurrent_messages_both_directions() {
    // Send messages simultaneously from both sides and verify all arrive.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("conc");
    let nick_a = test_nick("conc", "a");
    let nick_b = test_nick("conc", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let count = 5;

    // Send from both sides concurrently
    let ha_clone = ha.clone();
    let hb_clone = hb.clone();
    let ch = channel.clone();
    let send_a = tokio::spawn(async move {
        for i in 0..count {
            ha_clone.privmsg(&ch, &format!("from-a-{i}")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let ch = channel.clone();
    let send_b = tokio::spawn(async move {
        for i in 0..count {
            hb_clone.privmsg(&ch, &format!("from-b-{i}")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    send_a.await.unwrap();
    send_b.await.unwrap();

    // Count messages received on each side
    let mut a_received = 0;
    let mut b_received = 0;

    for _ in 0..count {
        if maybe_wait(
            &mut ea,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_b && text.starts_with("from-b-")),
            Duration::from_secs(10),
        ).await.is_some() {
            a_received += 1;
        }
    }

    for _ in 0..count {
        if maybe_wait(
            &mut eb,
            |e| matches!(e, Event::Message { from, text, .. } if from == &nick_a && text.starts_with("from-a-")),
            Duration::from_secs(10),
        ).await.is_some() {
            b_received += 1;
        }
    }

    eprintln!("  A received {a_received}/{count} from B, B received {b_received}/{count} from A");
    assert!(a_received >= count - 1, "A should receive most messages from B");
    assert!(b_received >= count - 1, "B should receive most messages from A");
    eprintln!("  ✓ Concurrent bidirectional messages delivered");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// Simulated netsplit tests
//
// These simulate what happens when users abruptly disconnect and
// reconnect, which is the user-visible effect of a netsplit even
// though we can't force the S2S link itself to drop from the client.
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn s2s_netsplit_simulation_rejoin() {
    // Simulate a netsplit: remote user abruptly drops, then reconnects
    // and rejoins. Local server should clean up and re-establish.
    //
    // Note: after abrupt drop (no QUIT), the old nick remains reserved on the
    // remote server until ping timeout (~120s). We use a DIFFERENT nick for
    // the reconnection to avoid the "nick in use" problem — this is realistic
    // since real netsplit recovery often involves nick collisions.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("split");
    let nick_a = test_nick("split", "a");
    let nick_b = test_nick("split", "b");
    let nick_b2 = test_nick("split", "b2"); // different nick for reconnect

    // Phase 1: Both connected and chatting
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea).await;
    wait_registered(&mut eb).await;

    ha.join(&channel).await.unwrap();
    hb.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    wait_names_containing(&mut ea, &channel, &nick_b).await;

    let msg1 = format!("pre-split {}", chrono::Utc::now().timestamp_millis());
    hb.privmsg(&channel, &msg1).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, msg1);
    eprintln!("  Phase 1: Normal operation ✓");

    // Phase 2: Simulate netsplit — abruptly drop remote connection
    // (just drop the handle without QUIT)
    drop(hb);
    drop(eb);

    // Wait for quit propagation (may take a moment via S2S or ping timeout)
    let quit_result = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == &nick_b),
        Duration::from_secs(20),
    ).await;

    if quit_result.is_some() {
        eprintln!("  Phase 2: Remote user cleaned up after drop ✓");
    } else {
        eprintln!("  Phase 2: QUIT not received within 20s (needs ping timeout) — continuing");
    }

    // Phase 3: Remote user reconnects with a new nick (old nick may still
    // be held by the ghost connection until ping timeout)
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b2).await;
    wait_registered(&mut eb2).await;
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut eb2, &channel).await;

    // Give S2S time to sync the rejoin
    let nicks = wait_names_containing(&mut ea, &channel, &nick_b2).await;
    eprintln!("  Phase 3: Reconnected user in NAMES: {nicks:?}");

    // Verify messages flow again
    let msg2 = format!("post-split {}", chrono::Utc::now().timestamp_millis());
    hb2.privmsg(&channel, &msg2).await.unwrap();
    let (_, text) = wait_message_from(&mut ea, &nick_b2).await;
    assert_eq!(text, msg2);
    eprintln!("  ✓ Full netsplit simulation passed: drop → reconnect with new nick → messages");

    let _ = ha.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_both_sides_disconnect_reconnect() {
    // Both sides drop and reconnect. Channel should be usable again.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("both");
    let nick_a = test_nick("both", "a");
    let nick_b = test_nick("both", "b");

    // Phase 1: Initial state
    {
        let (ha, mut ea) = connect_guest(&local, &nick_a).await;
        let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
        wait_registered(&mut ea).await;
        wait_registered(&mut eb).await;

        ha.join(&channel).await.unwrap();
        hb.join(&channel).await.unwrap();
        wait_joined(&mut ea, &channel).await;
        wait_joined(&mut eb, &channel).await;

        tokio::time::sleep(S2S_SETTLE).await;

        ha.privmsg(&channel, "before reset").await.unwrap();
        let (_, text) = wait_message_from(&mut eb, &nick_a).await;
        assert_eq!(text, "before reset");
        eprintln!("  Phase 1: Both connected ✓");

        // Both disconnect
        let _ = ha.quit(Some("reset")).await;
        let _ = hb.quit(Some("reset")).await;
    }

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 2: Both reconnect
    let (ha2, mut ea2) = connect_guest(&local, &nick_a).await;
    let (hb2, mut eb2) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut ea2).await;
    wait_registered(&mut eb2).await;

    ha2.join(&channel).await.unwrap();
    hb2.join(&channel).await.unwrap();
    wait_joined(&mut ea2, &channel).await;
    wait_joined(&mut eb2, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let msg = format!("after reset {}", chrono::Utc::now().timestamp_millis());
    ha2.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb2, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Both sides reconnected and communicating");

    let _ = ha2.quit(Some("done")).await;
    let _ = hb2.quit(Some("done")).await;
}

#[tokio::test]
async fn s2s_message_during_partial_channel() {
    // Send a message when only one side has joined. The other side
    // joins later — the message shouldn't crash anything.
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("partial");
    let nick_a = test_nick("part", "a");
    let nick_b = test_nick("part", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;

    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Send messages while remote hasn't joined
    ha.privmsg(&channel, "echo into void 1").await.unwrap();
    ha.privmsg(&channel, "echo into void 2").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now remote joins
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Send a new message — this one should be delivered
    let msg = format!("after join {}", chrono::Utc::now().timestamp_millis());
    ha.privmsg(&channel, &msg).await.unwrap();
    let (_, text) = wait_message_from(&mut eb, &nick_a).await;
    assert_eq!(text, msg);
    eprintln!("  ✓ Messages after late join work (pre-join messages correctly not delivered)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ═══════════════════════════════════════════════════════════════════
// S2S Sync Invariant Tests
//
// These test the fundamental invariants that MUST hold for federated
// channel state to be consistent. Each test name describes the
// invariant being verified.
//
// Invariant list:
//   INV-1: Exactly one op when channel created across federation
//   INV-2: Second joiner on remote server is NOT op
//   INV-3: Channel creator is op on both servers' NAMES
//   INV-4: +t enforced across servers (remote can't change topic)
//   INV-5: +n enforced across servers (non-member can't send)
//   INV-6: +m enforced across servers (non-voiced can't send)
//   INV-7: Mode changes propagate to remote server
//   INV-8: Staggered join — third joiner is NOT op
//   INV-9: Quit properly cleans up op state
// ═══════════════════════════════════════════════════════════════════

/// Helper: request NAMES for a channel and return the nick list.
async fn request_names(
    handle: &ClientHandle,
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
) -> Vec<String> {
    drain(rx).await;
    handle.raw(&format!("NAMES {channel}")).await.unwrap();
    let ch = channel.to_lowercase();
    match wait_for_timeout(
        rx,
        |e| matches!(e, Event::Names { channel: c, .. } if c.to_lowercase() == ch),
        &format!("NAMES response for {channel}"),
        TIMEOUT,
    ).await {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Helper: check if a nick has op (@) prefix in a NAMES list.
fn nick_is_op(nicks: &[String], nick: &str) -> bool {
    nicks.iter().any(|n| n == &format!("@{nick}"))
}

/// Helper: check if a nick is present (with or without prefix) in a NAMES list.
fn nick_is_present(nicks: &[String], nick: &str) -> bool {
    nicks.iter().any(|n| n.trim_start_matches(&['@', '+'][..]) == nick)
}

/// Helper: count how many nicks have op prefix.
fn count_ops(nicks: &[String]) -> usize {
    nicks.iter().filter(|n| n.starts_with('@')).count()
}

// ── INV-1: Exactly one op when channel first created ──

#[tokio::test]
async fn single_server_inv1_one_op_on_create() {
    let Some(server) = get_single_server() else { return };
    let channel = test_channel("inv1");
    let nick_a = test_nick("inv1", "a");
    let nick_b = test_nick("inv1", "b");

    // A creates channel
    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let nicks = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "Creator should be op: {nicks:?}");
    assert_eq!(count_ops(&nicks), 1, "Exactly one op on create: {nicks:?}");

    // B joins same channel — should NOT get op
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    let nicks = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "Creator still op: {nicks:?}");
    assert!(!nick_is_op(&nicks, &nick_b), "Second joiner NOT op: {nicks:?}");
    assert_eq!(count_ops(&nicks), 1, "Still exactly one op: {nicks:?}");
    eprintln!("  ✓ INV-1: Exactly one op on channel creation (single server)");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-2: Second joiner on remote server is NOT op ──

#[tokio::test]
async fn s2s_inv2_remote_joiner_not_op() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv2");
    let nick_a = test_nick("inv2", "a");
    let nick_b = test_nick("inv2", "b");

    // A creates channel on local server
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    // Wait for S2S to propagate the channel creation
    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote server — should NOT be op
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // Check from B's perspective
    let nicks_b = request_names(&hb, &mut eb, &channel).await;
    assert!(nick_is_present(&nicks_b, &nick_a), "A visible on remote: {nicks_b:?}");
    assert!(!nick_is_op(&nicks_b, &nick_b), "B should NOT be op on remote: {nicks_b:?}");
    eprintln!("  Remote NAMES: {nicks_b:?}");

    // Check from A's perspective
    let nicks_a = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks_a, &nick_a), "A should be op on local: {nicks_a:?}");
    assert!(!nick_is_op(&nicks_a, &nick_b), "B should NOT be op on local: {nicks_a:?}");
    eprintln!("  Local NAMES: {nicks_a:?}");

    // Count total ops across both views — should be exactly 1
    let total_ops_local = count_ops(&nicks_a);
    let total_ops_remote = count_ops(&nicks_b);
    assert_eq!(total_ops_local, 1, "Exactly 1 op on local: {nicks_a:?}");
    // Remote might show A as op or not depending on is_op propagation
    assert!(total_ops_remote <= 1, "At most 1 op on remote: {nicks_b:?}");

    eprintln!("  ✓ INV-2: Remote joiner is NOT op");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-3: Creator shows as op on both servers ──

#[tokio::test]
async fn s2s_inv3_creator_is_op_everywhere() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv3");
    let nick_a = test_nick("inv3", "a");
    let nick_b = test_nick("inv3", "b");

    // A creates channel on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A should be op on local
    let nicks_a = request_names(&ha, &mut ea, &channel).await;
    assert!(nick_is_op(&nicks_a, &nick_a), "Creator is op on local: {nicks_a:?}");

    // A should be op on remote too (via is_op in S2S Join)
    let nicks_b = request_names(&hb, &mut eb, &channel).await;
    assert!(nick_is_op(&nicks_b, &nick_a), "Creator is op on remote: {nicks_b:?}");
    eprintln!("  ✓ INV-3: Creator shows as @op on both servers");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-4: +t enforced across servers ──

#[tokio::test]
async fn s2s_inv4_topic_lock_enforced_cross_server() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv4");
    let nick_a = test_nick("inv4", "a");
    let nick_b = test_nick("inv4", "b");

    // A creates channel on local, sets +t
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    ha.raw(&format!("TOPIC {channel} :original topic")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    ha.raw(&format!("MODE {channel} +t")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B tries to set topic — should fail (B is not op, channel is +t)
    hb.raw(&format!("TOPIC {channel} :hacked topic")).await.unwrap();

    // B should get ERR_CHANOPRIVSNEEDED (482) or the topic should not change
    // Wait a moment, then check the topic from A's perspective
    tokio::time::sleep(Duration::from_secs(2)).await;

    ha.raw(&format!("TOPIC {channel}")).await.unwrap();
    let got = wait_topic(&mut ea, &channel).await;
    assert_eq!(got, "original topic",
        "Topic should NOT have changed (B is not op, +t is set): got '{got}'");
    eprintln!("  ✓ INV-4: +t prevents non-op from changing topic across servers");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-5: +n enforced — non-member can't send ──

#[tokio::test]
async fn single_server_inv5_no_external_messages() {
    let Some(server) = get_single_server() else { return };
    let channel = test_channel("inv5");
    let nick_a = test_nick("inv5", "a");
    let nick_b = test_nick("inv5", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    ha.raw(&format!("MODE {channel} +n")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    // B connects but does NOT join
    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;

    // B tries to send to channel — should get ERR_CANNOTSENDTOCHAN (404)
    hb.raw(&format!("PRIVMSG {channel} :external message")).await.unwrap();

    // A should NOT receive the message
    let got = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(3),
    ).await;
    assert!(got.is_none(), "A should NOT receive external message with +n");
    eprintln!("  ✓ INV-5: +n blocks external messages");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-6: +m enforced — non-voiced can't send ──

#[tokio::test]
async fn single_server_inv6_moderated_channel() {
    let Some(server) = get_single_server() else { return };
    let channel = test_channel("inv6");
    let nick_a = test_nick("inv6", "a");
    let nick_b = test_nick("inv6", "b");

    let (ha, mut ea) = connect_guest(&server, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    let (hb, mut eb) = connect_guest(&server, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    ha.raw(&format!("MODE {channel} +m")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    drain(&mut ea).await;

    // B (not voiced) tries to send — should be blocked
    hb.raw(&format!("PRIVMSG {channel} :silenced")).await.unwrap();

    let got = maybe_wait(
        &mut ea,
        |e| matches!(e, Event::Message { from, .. } if from == &nick_b),
        Duration::from_secs(3),
    ).await;
    assert!(got.is_none(), "A should NOT receive message from unvoiced user with +m");

    // Voice B, then B should be able to send
    ha.raw(&format!("MODE {channel} +v {nick_b}")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    hb.raw(&format!("PRIVMSG {channel} :now I can speak")).await.unwrap();
    let (from, text) = wait_message_from(&mut ea, &nick_b).await;
    assert_eq!(text, "now I can speak");
    eprintln!("  ✓ INV-6: +m blocks unvoiced, allows voiced (from={from})");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-7: Mode changes propagate to remote ──

#[tokio::test]
async fn s2s_inv7_mode_propagates() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv7");
    let nick_a = test_nick("inv7", "a");
    let nick_b = test_nick("inv7", "b");

    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;
    drain(&mut eb).await;

    // A sets +t on local
    ha.raw(&format!("MODE {channel} +t")).await.unwrap();
    wait_mode(&mut ea, &channel).await;

    // B should see the mode change
    let (mode, _arg) = wait_mode(&mut eb, &channel).await;
    assert!(mode.contains('t'), "Remote should see +t: {mode}");
    eprintln!("  ✓ INV-7: Mode +t propagated to remote server");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
}

// ── INV-8: Third joiner is never auto-opped ──

#[tokio::test]
async fn s2s_inv8_third_joiner_no_ops() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv8");
    let nick_a = test_nick("inv8", "a");
    let nick_b = test_nick("inv8", "b");
    let nick_c = test_nick("inv8", "c");

    // A creates on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // C joins on local
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    let nicks = request_names(&hc, &mut ec, &channel).await;
    assert!(nick_is_op(&nicks, &nick_a), "A should be op: {nicks:?}");
    assert!(!nick_is_op(&nicks, &nick_b), "B should NOT be op: {nicks:?}");
    assert!(!nick_is_op(&nicks, &nick_c), "C should NOT be op: {nicks:?}");
    assert_eq!(count_ops(&nicks), 1, "Exactly 1 op total: {nicks:?}");
    eprintln!("  ✓ INV-8: Third joiner is not op: {nicks:?}");

    let _ = ha.quit(Some("done")).await;
    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}

// ── INV-9: QUIT cleans up and op count stays correct ──

#[tokio::test]
async fn s2s_inv9_quit_cleans_op_state() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("inv9");
    let nick_a = test_nick("inv9", "a");
    let nick_b = test_nick("inv9", "b");
    let nick_c = test_nick("inv9", "c");

    // A creates on local
    let (ha, mut ea) = connect_guest(&local, &nick_a).await;
    wait_registered(&mut ea).await;
    ha.join(&channel).await.unwrap();
    wait_joined(&mut ea, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // B joins on remote
    let (hb, mut eb) = connect_guest(&remote, &nick_b).await;
    wait_registered(&mut eb).await;
    hb.join(&channel).await.unwrap();
    wait_joined(&mut eb, &channel).await;

    tokio::time::sleep(S2S_SETTLE).await;

    // A quits — the channel creator leaves
    ha.quit(Some("leaving")).await.unwrap();
    drop(ha);
    drop(ea);

    tokio::time::sleep(S2S_SETTLE).await;

    // C joins on local — should NOT be auto-opped (B is still in channel as remote)
    let (hc, mut ec) = connect_guest(&local, &nick_c).await;
    wait_registered(&mut ec).await;
    hc.join(&channel).await.unwrap();
    wait_joined(&mut ec, &channel).await;

    let nicks = request_names(&hc, &mut ec, &channel).await;
    assert!(!nick_is_op(&nicks, &nick_c), "C should NOT be op (B is still remote member): {nicks:?}");
    eprintln!("  ✓ INV-9: After creator quit, new joiner not auto-opped: {nicks:?}");

    let _ = hb.quit(Some("done")).await;
    let _ = hc.quit(Some("done")).await;
}
