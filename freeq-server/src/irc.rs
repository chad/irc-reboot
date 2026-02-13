//! IRC message parsing and formatting.
//!
//! Implements a minimal subset of RFC 1459 / RFC 2812 message format,
//! plus IRCv3 message tags, CAP capability negotiation, and SASL support.

use std::collections::HashMap;
use std::fmt;

/// A parsed IRC message with optional IRCv3 tags.
#[derive(Debug, Clone)]
pub struct Message {
    /// IRCv3 message tags (key=value pairs).
    pub tags: HashMap<String, String>,
    /// Optional message prefix (server or user origin).
    pub prefix: Option<String>,
    /// The IRC command (e.g. "NICK", "PRIVMSG", "001").
    pub command: String,
    /// Command parameters.
    pub params: Vec<String>,
}

impl Message {
    /// Parse a raw IRC line into a Message, including optional tags.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return None;
        }

        let mut rest = line;

        // Parse tags: @key=value;key2=value2
        let tags = if rest.starts_with('@') {
            let end = rest.find(' ')?;
            let tag_str = &rest[1..end];
            rest = &rest[end + 1..];
            parse_tags(tag_str)
        } else {
            HashMap::new()
        };

        let prefix = if rest.starts_with(':') {
            let end = rest.find(' ')?;
            let pfx = rest[1..end].to_string();
            rest = &rest[end + 1..];
            Some(pfx)
        } else {
            None
        };

        let mut params = Vec::new();
        let command;

        if let Some(space) = rest.find(' ') {
            command = rest[..space].to_ascii_uppercase();
            rest = &rest[space + 1..];

            while !rest.is_empty() {
                if let Some(trailing) = rest.strip_prefix(':') {
                    params.push(trailing.to_string());
                    break;
                }
                if let Some(space) = rest.find(' ') {
                    params.push(rest[..space].to_string());
                    rest = &rest[space + 1..];
                } else {
                    params.push(rest.to_string());
                    break;
                }
            }
        } else {
            command = rest.to_ascii_uppercase();
        }

        Some(Message {
            tags,
            prefix,
            command,
            params,
        })
    }

    /// Create a new message with no prefix.
    pub fn new(command: &str, params: Vec<&str>) -> Self {
        Message {
            tags: HashMap::new(),
            prefix: None,
            command: command.to_string(),
            params: params.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a new message with a server prefix.
    pub fn from_server(server: &str, command: &str, params: Vec<&str>) -> Self {
        Message {
            tags: HashMap::new(),
            prefix: Some(server.to_string()),
            command: command.to_string(),
            params: params.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Write tags
        if !self.tags.is_empty() {
            write!(f, "@")?;
            let mut first = true;
            for (key, value) in &self.tags {
                if !first { write!(f, ";")?; }
                first = false;
                if value.is_empty() {
                    write!(f, "{key}")?;
                } else {
                    write!(f, "{key}={}", escape_tag_value(value))?;
                }
            }
            write!(f, " ")?;
        }

        if let Some(ref prefix) = self.prefix {
            write!(f, ":{prefix} ")?;
        }
        write!(f, "{}", self.command)?;
        for (i, param) in self.params.iter().enumerate() {
            if i == self.params.len() - 1 && (param.contains(' ') || param.starts_with(':') || param.is_empty()) {
                write!(f, " :{param}")?;
            } else {
                write!(f, " {param}")?;
            }
        }
        Ok(())
    }
}

/// Parse IRCv3 tag string: `key=value;key2=value2`
fn parse_tags(tag_str: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    for pair in tag_str.split(';') {
        if pair.is_empty() { continue; }
        if let Some((key, value)) = pair.split_once('=') {
            tags.insert(key.to_string(), unescape_tag_value(value));
        } else {
            tags.insert(pair.to_string(), String::new());
        }
    }
    tags
}

/// Unescape IRCv3 tag values.
fn unescape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(':') => result.push(';'),
                Some('s') => result.push(' '),
                Some('\\') => result.push('\\'),
                Some('r') => result.push('\r'),
                Some('n') => result.push('\n'),
                Some(other) => { result.push('\\'); result.push(other); }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Escape a value for IRCv3 tag encoding.
fn escape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ';' => result.push_str("\\:"),
            ' ' => result.push_str("\\s"),
            '\\' => result.push_str("\\\\"),
            '\r' => result.push_str("\\r"),
            '\n' => result.push_str("\\n"),
            _ => result.push(c),
        }
    }
    result
}

// Standard IRC numerics
pub const RPL_WELCOME: &str = "001";
pub const RPL_YOURHOST: &str = "002";
pub const RPL_CREATED: &str = "003";
pub const RPL_MYINFO: &str = "004";

// SASL numerics
pub const RPL_LOGGEDIN: &str = "900";
pub const RPL_SASLSUCCESS: &str = "903";
pub const ERR_SASLFAIL: &str = "904";
pub const ERR_SASLALREADY: &str = "907";

// CAP / channel numerics
pub const RPL_NAMREPLY: &str = "353";
pub const RPL_ENDOFNAMES: &str = "366";
pub const RPL_TOPIC: &str = "332";
pub const RPL_TOPICWHOTIME: &str = "333";
pub const RPL_NOTOPIC: &str = "331";

// Channel mode numerics
pub const RPL_CHANNELMODEIS: &str = "324";
pub const RPL_CREATIONTIME: &str = "329";
pub const RPL_BANLIST: &str = "367";
pub const RPL_ENDOFBANLIST: &str = "368";
pub const RPL_INVITELIST: &str = "346";
pub const RPL_ENDOFINVITELIST: &str = "347";

pub const ERR_BANNEDFROMCHAN: &str = "474";
pub const ERR_INVITEONLYCHAN: &str = "473";
pub const ERR_BADCHANNELKEY: &str = "475";

// Error numerics for channels
pub const ERR_NOTONCHANNEL: &str = "442";
pub const ERR_CHANOPRIVSNEEDED: &str = "482";
pub const ERR_USERNOTINCHANNEL: &str = "441";
pub const ERR_NEEDMOREPARAMS: &str = "461";
pub const ERR_UNKNOWNMODE: &str = "472";

// WHOIS numerics
pub const RPL_WHOISUSER: &str = "311";
pub const RPL_WHOISSERVER: &str = "312";
pub const RPL_WHOISSPECIAL: &str = "320";
pub const RPL_WHOISACCOUNT: &str = "330";
pub const RPL_ENDOFWHOIS: &str = "318";

// Errors
pub const ERR_UNKNOWNCOMMAND: &str = "421";
pub const ERR_NONICKNAMEGIVEN: &str = "431";
pub const ERR_NICKNAMEINUSE: &str = "433";
pub const ERR_NOSUCHNICK: &str = "401";
pub const ERR_NOTREGISTERED: &str = "451";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let msg = Message::parse("NICK alice").unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["alice"]);
        assert!(msg.tags.is_empty());
    }

    #[test]
    fn parse_with_prefix() {
        let msg = Message::parse(":server 001 alice :Welcome").unwrap();
        assert_eq!(msg.prefix.as_deref(), Some("server"));
        assert_eq!(msg.command, "001");
        assert_eq!(msg.params, vec!["alice", "Welcome"]);
    }

    #[test]
    fn parse_privmsg() {
        let msg = Message::parse(":alice!~a@host PRIVMSG #chan :hello world").unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#chan", "hello world"]);
    }

    #[test]
    fn parse_with_tags() {
        let msg = Message::parse("@content-type=image/jpeg;media-url=https://example.com/img.jpg :alice!a@host PRIVMSG #chan :photo").unwrap();
        assert_eq!(msg.tags.get("content-type").unwrap(), "image/jpeg");
        assert_eq!(msg.tags.get("media-url").unwrap(), "https://example.com/img.jpg");
        assert_eq!(msg.command, "PRIVMSG");
    }

    #[test]
    fn roundtrip() {
        let msg = Message::from_server("irc.example", "001", vec!["alice", "Welcome to IRC"]);
        let s = msg.to_string();
        assert_eq!(s, ":irc.example 001 alice :Welcome to IRC");
    }

    #[test]
    fn tag_escaping() {
        let original = "hello world;test";
        let escaped = escape_tag_value(original);
        assert_eq!(escaped, "hello\\sworld\\:test");
        assert_eq!(unescape_tag_value(&escaped), original);
    }
}
