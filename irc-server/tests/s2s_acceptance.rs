//! S2S federation acceptance tests.
//!
//! These tests connect to TWO live IRC servers and verify that state
//! syncs correctly between them. Run with:
//!
//!   LOCAL_SERVER=localhost:6667 REMOTE_SERVER=irc.freeq.at:6667 cargo test -p irc-server --test s2s_acceptance -- --nocapture --test-threads=1
//!
//! Both servers must be running with --iroh and S2S peering configured.
//! If environment variables aren't set, tests are skipped.
//!
//! NOTE: Use `--test-threads=1` to run sequentially. The single S2S link
//! between the two servers can't handle 9 concurrent test sessions reliably.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

use irc_at_sdk::client::{self, ClientHandle, ConnectConfig};
use irc_at_sdk::event::Event;

/// How long to wait for an event before considering it failed.
const TIMEOUT: Duration = Duration::from_secs(15);

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
    .expect(&format!("Failed to connect to {addr}"));

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
    let result = timeout(TIMEOUT, async {
        loop {
            match rx.recv().await {
                Some(evt) if predicate(&evt) => return evt,
                Some(_) => continue,
                None => panic!("Channel closed while waiting for: {desc}"),
            }
        }
    })
    .await;

    result.unwrap_or_else(|_| panic!("Timeout waiting for: {desc}"))
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
    let ch = channel.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Joined { channel: c, .. } if c == &ch),
        &format!("Joined {channel}"),
    )
    .await
    {
        Event::Joined { nick, .. } => nick,
        _ => unreachable!(),
    }
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

/// Wait for a Names event that includes a specific nick.
async fn wait_names_containing(
    rx: &mut mpsc::Receiver<Event>,
    channel: &str,
    nick: &str,
) -> Vec<String> {
    let ch = channel.to_string();
    let n = nick.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::Names { channel: c, nicks } if c == &ch && nicks.iter().any(|x| x.trim_start_matches('@') == n)),
        &format!("Names in {channel} containing {nick}"),
    )
    .await
    {
        Event::Names { nicks, .. } => nicks,
        _ => unreachable!(),
    }
}

/// Wait for a TopicChanged event.
async fn wait_topic(rx: &mut mpsc::Receiver<Event>, channel: &str) -> String {
    let ch = channel.to_string();
    match wait_for(
        rx,
        |e| matches!(e, Event::TopicChanged { channel: c, .. } if c == &ch),
        &format!("Topic in {channel}"),
    )
    .await
    {
        Event::TopicChanged { topic, .. } => topic,
        _ => unreachable!(),
    }
}

fn get_servers() -> Option<(String, String)> {
    let local = std::env::var("LOCAL_SERVER").ok();
    let remote = std::env::var("REMOTE_SERVER").ok();
    match (local, remote) {
        (Some(l), Some(r)) => Some((l, r)),
        _ => {
            eprintln!("Skipping S2S acceptance tests: set LOCAL_SERVER and REMOTE_SERVER env vars");
            None
        }
    }
}

/// Generate a unique channel name to avoid interference between test runs.
fn test_channel(suffix: &str) -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("#t{}{}", ts % 100000, suffix)
}

// ── Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_both_servers_accept_connections() {
    let Some((local, remote)) = get_servers() else { return };

    let (h1, mut e1) = connect_guest(&local, "s2s_test_a1").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_test_b1").await;

    let nick1 = wait_registered(&mut e1).await;
    let nick2 = wait_registered(&mut e2).await;

    eprintln!("  Local registered as: {nick1}");
    eprintln!("  Remote registered as: {nick2}");

    let _ = h1.quit(Some("test done")).await;
    let _ = h2.quit(Some("test done")).await;
}

#[tokio::test]
async fn test_messages_relay_local_to_remote() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("msg");

    let (h1, mut e1) = connect_guest(&local, "s2s_msg_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_msg_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    // Both join the same channel
    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();

    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    // Give S2S time to sync JOINs
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send message from local
    let test_msg = format!("hello from local {}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    h1.privmsg(&channel, &test_msg).await.unwrap();

    // Remote should receive it
    let (target, text) = wait_message_from(&mut e2, "s2s_msg_a").await;
    assert_eq!(target, channel);
    assert_eq!(text, test_msg);
    eprintln!("  ✓ Message relayed local→remote: {test_msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_messages_relay_remote_to_local() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("rmsg");

    let (h1, mut e1) = connect_guest(&local, "s2s_rmsg_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_rmsg_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let test_msg = format!("hello from remote {}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    h2.privmsg(&channel, &test_msg).await.unwrap();

    let (target, text) = wait_message_from(&mut e1, "s2s_rmsg_b").await;
    assert_eq!(target, channel);
    assert_eq!(text, test_msg);
    eprintln!("  ✓ Message relayed remote→local: {test_msg}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_remote_user_appears_in_names() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("nm");

    let (h1, mut e1) = connect_guest(&local, "s2s_nm_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_nm_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    // Local joins first
    h1.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;

    // Remote joins — local should get updated NAMES containing the remote user
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    // Wait for NAMES update on local that includes the remote user
    let nicks = wait_names_containing(&mut e1, &channel, "s2s_nm_b").await;
    eprintln!("  ✓ Remote user in NAMES: {nicks:?}");

    // Verify local user is also there
    assert!(
        nicks.iter().any(|n| n.trim_start_matches('@') == "s2s_nm_a"),
        "Local user should also be in NAMES: {nicks:?}"
    );

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_topic_syncs_to_remote() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("top");

    let (h1, mut e1) = connect_guest(&local, "s2s_top_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_top_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Set topic from local
    let topic_text = format!("test topic {}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    h1.raw(&format!("TOPIC {channel} :{topic_text}")).await.unwrap();

    // Remote should see topic change
    let received_topic = wait_topic(&mut e2, &channel).await;
    assert_eq!(received_topic, topic_text);
    eprintln!("  ✓ Topic synced: {topic_text}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_part_removes_remote_user_from_names() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("part");

    let (h1, mut e1) = connect_guest(&local, "s2s_part_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_part_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    // Wait for remote user to appear
    wait_names_containing(&mut e1, &channel, "s2s_part_b").await;

    // Remote parts
    h2.raw(&format!("PART {channel}")).await.unwrap();

    // Local should see the part
    let evt = wait_for(
        &mut e1,
        |e| matches!(e, Event::Parted { channel: c, nick } if c == &channel && nick == "s2s_part_b"),
        "Part from s2s_part_b",
    )
    .await;
    eprintln!("  ✓ Remote user parted: {evt:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_quit_removes_remote_user() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("quit");

    let (h1, mut e1) = connect_guest(&local, "s2s_quit_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_quit_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    // Wait for remote user to appear
    wait_names_containing(&mut e1, &channel, "s2s_quit_b").await;

    // Remote quits
    h2.quit(Some("testing quit")).await.unwrap();

    // Local should see the quit
    let evt = wait_for(
        &mut e1,
        |e| matches!(e, Event::UserQuit { nick, .. } if nick == "s2s_quit_b"),
        "Quit from s2s_quit_b",
    )
    .await;
    eprintln!("  ✓ Remote user quit: {evt:?}");

    let _ = h1.quit(Some("done")).await;
}

#[tokio::test]
async fn test_bidirectional_messages() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("bidir");

    let (h1, mut e1) = connect_guest(&local, "s2s_bidir_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_bidir_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    h1.join(&channel).await.unwrap();
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e1, &channel).await;
    wait_joined(&mut e2, &channel).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Local → Remote
    h1.privmsg(&channel, "ping from local").await.unwrap();
    let (_, text) = wait_message_from(&mut e2, "s2s_bidir_a").await;
    assert_eq!(text, "ping from local");

    // Remote → Local
    h2.privmsg(&channel, "pong from remote").await.unwrap();
    let (_, text) = wait_message_from(&mut e1, "s2s_bidir_b").await;
    assert_eq!(text, "pong from remote");

    eprintln!("  ✓ Bidirectional message relay works");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}

#[tokio::test]
async fn test_late_joiner_sees_existing_remote_user() {
    let Some((local, remote)) = get_servers() else { return };
    let channel = test_channel("late");

    let (h1, mut e1) = connect_guest(&local, "s2s_late_a").await;
    let (h2, mut e2) = connect_guest(&remote, "s2s_late_b").await;

    wait_registered(&mut e1).await;
    wait_registered(&mut e2).await;

    // Remote joins first
    h2.join(&channel).await.unwrap();
    wait_joined(&mut e2, &channel).await;

    // Give S2S time to propagate (longer when running all tests concurrently)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Local joins later — should see remote user in NAMES
    h1.join(&channel).await.unwrap();

    // Wait for NAMES (including any subsequent S2S-triggered NAMES updates)
    // that includes the remote user. Under concurrent load, the initial
    // NAMES on JOIN may arrive before the S2S JOIN has propagated, so we
    // keep waiting for updated NAMES that include the remote user.
    let nicks = wait_names_containing(&mut e1, &channel, "s2s_late_b").await;
    eprintln!("  ✓ Late joiner sees existing remote user: {nicks:?}");

    let _ = h1.quit(Some("done")).await;
    let _ = h2.quit(Some("done")).await;
}
