//! Bot framework for building IRC bots on freeq.
//!
//! Provides command routing, permission checks, and automatic help generation.
//!
//! # Example
//!
//! ```rust,no_run
//! use freeq_sdk::bot::{Bot, CommandContext};
//!
//! let mut bot = Bot::new("!", "mybot");
//! bot.command("ping", "Reply with pong", |ctx| {
//!     Box::pin(async move { ctx.reply("pong!").await })
//! });
//! bot.command("echo", "Echo your message", |ctx| {
//!     Box::pin(async move {
//!         let text = ctx.args_str();
//!         if text.is_empty() {
//!             ctx.reply("Usage: !echo <message>").await
//!         } else {
//!             ctx.reply(&text).await
//!         }
//!     })
//! });
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::client::ClientHandle;
use crate::event::Event;

/// Context passed to command handlers.
pub struct CommandContext {
    /// The bot's client handle for sending messages.
    pub handle: ClientHandle,
    /// Nick of the user who invoked the command.
    pub sender: String,
    /// Channel or nick the command was sent to.
    pub target: String,
    /// The command name (without prefix).
    pub command: String,
    /// Arguments after the command.
    pub args: Vec<String>,
    /// Full argument string (everything after the command).
    pub args_raw: String,
    /// Whether this was sent in a channel (vs PM).
    pub is_channel: bool,
    /// Sender's DID if known (from IRCv3 tags).
    pub sender_did: Option<String>,
    /// All IRCv3 message tags.
    pub tags: HashMap<String, String>,
}

impl CommandContext {
    /// Full argument string.
    pub fn args_str(&self) -> String {
        self.args_raw.clone()
    }

    /// Reply to the channel/user.
    pub async fn reply(&self, text: &str) -> anyhow::Result<()> {
        let target = if self.is_channel {
            &self.target
        } else {
            &self.sender
        };
        self.handle.privmsg(target, text).await
    }

    /// Reply with a prefix mentioning the sender.
    pub async fn reply_to(&self, text: &str) -> anyhow::Result<()> {
        self.reply(&format!("{}: {text}", self.sender)).await
    }
}

/// A command handler function.
type Handler = Arc<
    dyn Fn(CommandContext) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Permission level for commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    /// Anyone can use this command.
    Anyone,
    /// Only authenticated users (with a DID).
    Authenticated,
    /// Only specific DIDs (configured per-command).
    Admin,
}

struct CommandEntry {
    name: String,
    description: String,
    permission: Permission,
    handler: Handler,
    /// For Admin permission: allowed DIDs.
    allowed_dids: Vec<String>,
}

/// An IRC bot with command routing.
pub struct Bot {
    /// Command prefix (e.g. "!", ".", "bot:").
    prefix: String,
    /// Bot's nick (for PM detection).
    nick: String,
    /// Registered commands.
    commands: Vec<CommandEntry>,
    /// Admin DIDs (can use any Admin-level command).
    admin_dids: Vec<String>,
    /// Called for messages that don't match any command.
    fallback: Option<Handler>,
}

impl Bot {
    /// Create a new bot with the given command prefix and nick.
    pub fn new(prefix: &str, nick: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            nick: nick.to_string(),
            commands: Vec::new(),
            admin_dids: Vec::new(),
            fallback: None,
        }
    }

    /// Add a global admin DID.
    pub fn admin(mut self, did: &str) -> Self {
        self.admin_dids.push(did.to_string());
        self
    }

    /// Register a command available to anyone.
    pub fn command<F>(&mut self, name: &str, description: &str, handler: F)
    where
        F: Fn(CommandContext) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.commands.push(CommandEntry {
            name: name.to_string(),
            description: description.to_string(),
            permission: Permission::Anyone,
            handler: Arc::new(handler),
            allowed_dids: Vec::new(),
        });
    }

    /// Register a command requiring authentication.
    pub fn auth_command<F>(&mut self, name: &str, description: &str, handler: F)
    where
        F: Fn(CommandContext) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.commands.push(CommandEntry {
            name: name.to_string(),
            description: description.to_string(),
            permission: Permission::Authenticated,
            handler: Arc::new(handler),
            allowed_dids: Vec::new(),
        });
    }

    /// Register an admin-only command.
    pub fn admin_command<F>(&mut self, name: &str, description: &str, handler: F)
    where
        F: Fn(CommandContext) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.commands.push(CommandEntry {
            name: name.to_string(),
            description: description.to_string(),
            permission: Permission::Admin,
            handler: Arc::new(handler),
            allowed_dids: Vec::new(),
        });
    }

    /// Set a fallback handler for non-command messages.
    pub fn on_message<F>(&mut self, handler: F)
    where
        F: Fn(CommandContext) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        self.fallback = Some(Arc::new(handler));
    }

    /// Process an event. Call this in your event loop.
    pub async fn handle_event(&self, handle: &ClientHandle, event: &Event) {
        match event {
            Event::Message {
                from,
                target,
                text,
                tags,
            } => {
                let is_channel = target.starts_with('#') || target.starts_with('&');
                let sender_did = tags.get("account").cloned();

                if let Some(cmd_text) = text.strip_prefix(&self.prefix) {
                    let parts: Vec<&str> = cmd_text.splitn(2, ' ').collect();
                    let cmd_name = parts[0].to_lowercase();
                    let args_raw = parts.get(1).unwrap_or(&"").to_string();
                    let args: Vec<String> = if args_raw.is_empty() {
                        Vec::new()
                    } else {
                        args_raw.split_whitespace().map(|s| s.to_string()).collect()
                    };

                    // Built-in help command
                    if cmd_name == "help" {
                        let _ = self.send_help(handle, if is_channel { target } else { from }).await;
                        return;
                    }

                    // Find matching command
                    if let Some(entry) = self.commands.iter().find(|c| c.name == cmd_name) {
                        // Check permissions
                        match entry.permission {
                            Permission::Anyone => {}
                            Permission::Authenticated => {
                                if sender_did.is_none() {
                                    let reply_target = if is_channel { target } else { from };
                                    let _ = handle
                                        .privmsg(reply_target, "This command requires authentication.")
                                        .await;
                                    return;
                                }
                            }
                            Permission::Admin => {
                                let is_admin = sender_did.as_ref().is_some_and(|d| {
                                    self.admin_dids.contains(d) || entry.allowed_dids.contains(d)
                                });
                                if !is_admin {
                                    let reply_target = if is_channel { target } else { from };
                                    let _ = handle
                                        .privmsg(reply_target, "Permission denied.")
                                        .await;
                                    return;
                                }
                            }
                        }

                        let ctx = CommandContext {
                            handle: handle.clone(),
                            sender: from.clone(),
                            target: target.clone(),
                            command: cmd_name,
                            args,
                            args_raw,
                            is_channel,
                            sender_did,
                            tags: tags.clone(),
                        };

                        if let Err(e) = (entry.handler)(ctx).await {
                            tracing::warn!(command = %entry.name, error = %e, "Command handler error");
                        }
                    }
                } else if let Some(ref fallback) = self.fallback {
                    let ctx = CommandContext {
                        handle: handle.clone(),
                        sender: from.clone(),
                        target: target.clone(),
                        command: String::new(),
                        args: text.split_whitespace().map(|s| s.to_string()).collect(),
                        args_raw: text.clone(),
                        is_channel,
                        sender_did,
                        tags: tags.clone(),
                    };
                    if let Err(e) = (fallback)(ctx).await {
                        tracing::warn!(error = %e, "Fallback handler error");
                    }
                }
            }
            _ => {}
        }
    }

    /// Send help listing all commands.
    async fn send_help(&self, handle: &ClientHandle, target: &str) -> anyhow::Result<()> {
        let mut lines = vec![format!("Commands (prefix: {}):", self.prefix)];
        for entry in &self.commands {
            let perm = match entry.permission {
                Permission::Anyone => "",
                Permission::Authenticated => " [auth]",
                Permission::Admin => " [admin]",
            };
            lines.push(format!(
                "  {}{} — {}{}",
                self.prefix, entry.name, entry.description, perm
            ));
        }
        lines.push(format!("  {}help — Show this help", self.prefix));
        for line in lines {
            handle.privmsg(target, &line).await?;
        }
        Ok(())
    }
}
