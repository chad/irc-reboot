//! Minimal echo bot example for freeq.
//!
//! Demonstrates using the freeq SDK to build a bot that:
//! - Connects to a freeq/IRC server as a guest
//! - Joins a channel
//! - Responds to !echo, !ping, !help commands
//! - Shows how to handle events
//!
//! Usage:
//!   cargo run --example echo_bot -- --server localhost:6667 --nick echobot --channel "#test"
//!
//! The bot connects as a guest (no AT Protocol auth). For an authenticated
//! bot, use PdsSessionSigner or KeySigner — see the auth module.

use anyhow::Result;
use clap::Parser;
use freeq_sdk::client::{self, ClientHandle, ConnectConfig};
use freeq_sdk::event::Event;

#[derive(Parser)]
#[command(name = "echo-bot", about = "Minimal freeq echo bot")]
struct Args {
    /// Server address (host:port)
    #[arg(long, default_value = "localhost:6667")]
    server: String,

    /// Bot nick
    #[arg(long, default_value = "echobot")]
    nick: String,

    /// Channel to join
    #[arg(long, default_value = "#bots")]
    channel: String,

    /// Use TLS
    #[arg(long)]
    tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("Connecting to {} as {}...", args.server, args.nick);

    let conn = client::establish_connection(&ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Freeq Echo Bot".to_string(),
        tls: args.tls,
        tls_insecure: false,
    })
    .await?;

    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Freeq Echo Bot".to_string(),
        tls: args.tls,
        tls_insecure: false,
    };

    // No signer = guest mode (no AT Protocol authentication)
    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    // Join the channel after registration
    let channel = args.channel.clone();
    let handle_clone = handle.clone();
    tokio::spawn(async move {
        // Wait a moment for registration to complete
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = handle_clone.join(&channel).await;
        println!("Joined {channel}");
    });

    // Event loop
    println!("Bot running. Press Ctrl-C to stop.");
    loop {
        match events.recv().await {
            Some(event) => handle_event(&handle, &args, event).await?,
            None => {
                println!("Event channel closed, exiting");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_event(handle: &ClientHandle, args: &Args, event: Event) -> Result<()> {
    match event {
        Event::Connected => println!("Connected!"),
        Event::Registered { nick } => println!("Registered as {nick}"),

        Event::Message {
            from,
            target,
            text,
            ..
        } => {
            // Only respond to channel messages (not PMs) in our channel
            let is_channel = target.starts_with('#') || target.starts_with('&');
            if !is_channel {
                return Ok(());
            }

            // Parse commands
            if let Some(cmd) = text.strip_prefix('!') {
                let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
                let command = parts[0];
                let arg = parts.get(1).unwrap_or(&"");

                match command {
                    "echo" => {
                        if !arg.is_empty() {
                            handle.privmsg(&target, arg).await?;
                        } else {
                            handle.privmsg(&target, "Usage: !echo <message>").await?;
                        }
                    }
                    "ping" => {
                        handle.privmsg(&target, &format!("{from}: pong!")).await?;
                    }
                    "help" => {
                        handle
                            .privmsg(
                                &target,
                                "Commands: !echo <msg>, !ping, !help, !about",
                            )
                            .await?;
                    }
                    "about" => {
                        handle
                            .privmsg(
                                &target,
                                "I'm a freeq echo bot. Source: examples/echo_bot.rs",
                            )
                            .await?;
                    }
                    _ => {} // Ignore unknown commands
                }
            }
        }

        Event::Joined {
            channel, nick, ..
        } => {
            if nick != args.nick {
                println!("{nick} joined {channel}");
            }
        }

        Event::Parted { channel, nick, .. } => {
            println!("{nick} left {channel}");
        }

        Event::Disconnected { reason } => {
            println!("Disconnected: {reason}");
            std::process::exit(1);
        }

        _ => {} // Ignore other events
    }

    Ok(())
}
