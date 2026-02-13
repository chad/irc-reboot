//! Server plugin system.
//!
//! Plugins hook into server events to add custom behavior. They are
//! compiled into the binary and activated by name via:
//!
//! - CLI: `--plugin name:key=value,key2=value2`
//! - Plugin directory: `--plugin-dir ./plugins/` (loads `*.toml` files)
//! - Inline in server config
//!
//! # Writing a plugin
//!
//! 1. Implement the [`Plugin`] trait
//! 2. Register it in [`builtin_plugins`]
//! 3. Activate it by name when starting the server
//!
//! # Example plugin config (`plugins/leet.toml`)
//!
//! ```toml
//! name = "identity-override"
//!
//! [[rules]]
//! handle = "timesync.bsky.social"
//! display_id = "3|337"
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Event emitted when a user successfully authenticates via SASL.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    /// The DID that was authenticated (e.g. "did:plc:abc123").
    pub did: String,
    /// The resolved AT Protocol handle, if available (e.g. "timesync.bsky.social").
    pub handle: Option<String>,
    /// The IRC nick the user registered with.
    pub nick: String,
    /// The session ID for this connection.
    pub session_id: String,
}

/// Result of a plugin processing an auth event.
/// Plugins can override what identity is displayed to other users.
#[derive(Debug, Clone, Default)]
pub struct AuthResult {
    /// If set, this replaces the DID in session_dids (what WHOIS shows).
    pub override_did: Option<String>,
    /// If set, this replaces the handle in session_handles.
    pub override_handle: Option<String>,
}

/// Trait that all plugins implement.
pub trait Plugin: Send + Sync {
    /// Human-readable name of this plugin.
    fn name(&self) -> &str;

    /// Called after a user successfully authenticates.
    /// Return an `AuthResult` to override displayed identity.
    fn on_auth(&self, event: &AuthEvent) -> Option<AuthResult> {
        let _ = event;
        None
    }
}

/// A factory function that creates a plugin instance from config.
type PluginFactory = fn(config: &HashMap<String, String>) -> Box<dyn Plugin>;

/// Return the registry of built-in plugin factories.
fn builtin_plugins() -> HashMap<&'static str, PluginFactory> {
    let mut m: HashMap<&'static str, PluginFactory> = HashMap::new();
    m.insert("identity-override", |config| {
        Box::new(IdentityOverridePlugin::from_config(config))
    });
    m
}

/// Manages loaded plugins and dispatches events.
pub struct PluginManager {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Load plugins from all sources: CLI args, plugin directory, etc.
    pub fn load(
        plugin_args: &[String],
        plugin_dir: Option<&str>,
    ) -> Self {
        let mut mgr = Self::new();
        let registry = builtin_plugins();

        // Load from --plugin args: "name" or "name:key=val,key2=val2"
        for arg in plugin_args {
            let (name, config) = parse_plugin_arg(arg);
            if let Some(factory) = registry.get(name.as_str()) {
                let plugin = factory(&config);
                tracing::info!("Loaded plugin '{}' from CLI", plugin.name());
                mgr.plugins.push(plugin);
            } else {
                tracing::warn!("Unknown plugin '{name}' — skipping");
            }
        }

        // Load from --plugin-dir: each *.toml file is a plugin config
        if let Some(dir) = plugin_dir {
            let path = Path::new(dir);
            if path.is_dir() {
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().is_some_and(|e| e == "toml") {
                            match load_plugin_toml(&p, &registry) {
                                Ok(plugin) => {
                                    tracing::info!(
                                        "Loaded plugin '{}' from {}",
                                        plugin.name(),
                                        p.display()
                                    );
                                    mgr.plugins.push(plugin);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to load plugin from {}: {e}",
                                        p.display()
                                    );
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!("Plugin directory '{}' does not exist", dir);
            }
        }

        if !mgr.plugins.is_empty() {
            tracing::info!("Loaded {} plugin(s)", mgr.plugins.len());
        }

        mgr
    }

    /// Dispatch an auth event to all plugins. Returns the merged result.
    pub fn on_auth(&self, event: &AuthEvent) -> AuthResult {
        let mut result = AuthResult::default();
        for plugin in &self.plugins {
            if let Some(r) = plugin.on_auth(event) {
                // Last plugin wins for each field
                if r.override_did.is_some() {
                    result.override_did = r.override_did;
                }
                if r.override_handle.is_some() {
                    result.override_handle = r.override_handle;
                }
            }
        }
        result
    }

    /// Returns true if any plugins are loaded.
    pub fn has_plugins(&self) -> bool {
        !self.plugins.is_empty()
    }
}

// ── Built-in plugins ────────────────────────────────────────────

/// Plugin that overrides the displayed identity for specific users.
///
/// Config keys (flat, for CLI):
///   handle=timesync.bsky.social
///   display_id=3|337
///
/// Or via TOML with multiple rules:
/// ```toml
/// name = "identity-override"
/// [[rules]]
/// handle = "timesync.bsky.social"
/// display_id = "3|337"
/// ```
struct IdentityOverridePlugin {
    rules: Vec<OverrideRule>,
}

#[derive(Debug, Clone)]
struct OverrideRule {
    /// Match on AT Protocol handle (case-insensitive).
    handle: Option<String>,
    /// Match on DID (exact).
    did: Option<String>,
    /// What to display instead of the DID.
    display_id: String,
}

impl IdentityOverridePlugin {
    fn from_config(config: &HashMap<String, String>) -> Self {
        // Simple single-rule from CLI args
        let mut rules = Vec::new();
        if let Some(display_id) = config.get("display_id") {
            rules.push(OverrideRule {
                handle: config.get("handle").cloned(),
                did: config.get("did").cloned(),
                display_id: display_id.clone(),
            });
        }
        Self { rules }
    }

    fn from_toml(table: &toml::Value) -> Self {
        let mut rules = Vec::new();
        if let Some(rule_array) = table.get("rules").and_then(|v| v.as_array()) {
            for rule in rule_array {
                if let Some(display_id) = rule.get("display_id").and_then(|v| v.as_str()) {
                    rules.push(OverrideRule {
                        handle: rule.get("handle").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        did: rule.get("did").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        display_id: display_id.to_string(),
                    });
                }
            }
        }
        Self { rules }
    }
}

impl Plugin for IdentityOverridePlugin {
    fn name(&self) -> &str {
        "identity-override"
    }

    fn on_auth(&self, event: &AuthEvent) -> Option<AuthResult> {
        for rule in &self.rules {
            let matches = match (&rule.handle, &rule.did) {
                (Some(h), _) => event
                    .handle
                    .as_ref()
                    .is_some_and(|eh| eh.eq_ignore_ascii_case(h)),
                (_, Some(d)) => event.did == *d,
                _ => false,
            };
            if matches {
                tracing::info!(
                    "Plugin identity-override: {} → {}",
                    event.did,
                    rule.display_id
                );
                return Some(AuthResult {
                    override_did: Some(rule.display_id.clone()),
                    override_handle: None,
                });
            }
        }
        None
    }
}

// ── Parsing helpers ─────────────────────────────────────────────

/// Parse a CLI plugin arg like "name:key=val,key2=val2" into (name, config).
fn parse_plugin_arg(arg: &str) -> (String, HashMap<String, String>) {
    let mut config = HashMap::new();
    let (name, rest) = match arg.split_once(':') {
        Some((n, r)) => (n.to_string(), r),
        None => return (arg.to_string(), config),
    };
    for pair in rest.split(',') {
        if let Some((k, v)) = pair.split_once('=') {
            config.insert(k.to_string(), v.to_string());
        }
    }
    (name, config)
}

/// Load a plugin from a TOML config file.
fn load_plugin_toml(
    path: &Path,
    registry: &HashMap<&str, PluginFactory>,
) -> Result<Box<dyn Plugin>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    let table: toml::Value =
        content.parse().map_err(|e| format!("TOML parse error: {e}"))?;

    let name = table
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'name' field".to_string())?;

    // Special handling for plugins that need the full TOML table
    match name {
        "identity-override" => {
            Ok(Box::new(IdentityOverridePlugin::from_toml(&table)))
        }
        _ => {
            // Fall back to generic factory with flat config
            let factory = registry
                .get(name)
                .ok_or_else(|| format!("unknown plugin: {name}"))?;
            let flat: HashMap<String, String> = table
                .as_table()
                .map(|t| {
                    t.iter()
                        .filter(|(k, _)| *k != "name" && *k != "rules")
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            Ok(factory(&flat))
        }
    }
}
