//! Bot framework example — demonstrates the freeq bot framework.
//!
//! Shows command routing, permission levels, and help generation.
//!
//! Usage:
//!   cargo run --example framework_bot -- --server localhost:6667 --channel "#bots"

use anyhow::Result;
use clap::Parser;
use freeq_sdk::bot::Bot;
use freeq_sdk::client::{self, ConnectConfig};
use freeq_sdk::event::Event;

#[derive(Parser)]
#[command(name = "framework-bot", about = "Freeq bot framework example")]
struct Args {
    #[arg(long, default_value = "localhost:6667")]
    server: String,
    #[arg(long, default_value = "freeqbot")]
    nick: String,
    #[arg(long, default_value = "#bots")]
    channel: String,
    #[arg(long)]
    tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Build the bot with commands
    let mut bot = Bot::new("!", &args.nick);

    bot.command("ping", "Reply with pong", |ctx| {
        Box::pin(async move { ctx.reply_to("pong!").await })
    });

    bot.command("echo", "Echo your message back", |ctx| {
        Box::pin(async move {
            let text = ctx.args_str();
            if text.is_empty() {
                ctx.reply("Usage: !echo <message>").await
            } else {
                ctx.reply(&text).await
            }
        })
    });

    bot.command("whoami", "Show your identity", |ctx| {
        Box::pin(async move {
            let info = match &ctx.sender_did {
                Some(did) => format!("{}: authenticated as {did}", ctx.sender),
                None => format!("{}: guest (not authenticated)", ctx.sender),
            };
            ctx.reply(&info).await
        })
    });

    bot.auth_command("secret", "Only for authenticated users", |ctx| {
        Box::pin(async move {
            ctx.reply(&format!(
                "Welcome, {}! Your DID: {}",
                ctx.sender,
                ctx.sender_did.as_deref().unwrap_or("?")
            ))
            .await
        })
    });

    // Connect
    let config = ConnectConfig {
        server_addr: args.server.clone(),
        nick: args.nick.clone(),
        user: args.nick.clone(),
        realname: "Freeq Framework Bot".to_string(),
        tls: args.tls,
        tls_insecure: false,
    };

    let conn = client::establish_connection(&config).await?;
    let (handle, mut events) = client::connect_with_stream(conn, config, None);

    let channel = args.channel.clone();
    let h = handle.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let _ = h.join(&channel).await;
    });

    println!("Bot running. Commands: !ping !echo !whoami !secret !help");
    loop {
        match events.recv().await {
            Some(event) => {
                if let Event::Disconnected { reason } = &event {
                    println!("Disconnected: {reason}");
                    break;
                }
                bot.handle_event(&handle, &event).await;
            }
            None => break,
        }
    }
    Ok(())
}
