//! IRC message types — shared between SDK and server.
//! This is a minimal parser/formatter for IRC protocol lines.
//!
//! Supports IRCv3 message tags: `@key=value;key2=value2 :prefix COMMAND params`

use std::collections::HashMap;
use std::fmt;

/// A parsed IRC message with optional IRCv3 tags.
#[derive(Debug, Clone)]
pub struct Message {
    /// IRCv3 message tags (key=value pairs).
    pub tags: HashMap<String, String>,
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    /// Parse a raw IRC line, including optional message tags.
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

        // Parse prefix: :server or :nick!user@host
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

    pub fn new(command: &str, params: Vec<&str>) -> Self {
        Self {
            tags: HashMap::new(),
            prefix: None,
            command: command.to_string(),
            params: params.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Create a message with tags.
    pub fn with_tags(tags: HashMap<String, String>, command: &str, params: Vec<&str>) -> Self {
        Self {
            tags,
            prefix: None,
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
            if i == self.params.len() - 1
                && (param.contains(' ') || param.starts_with(':') || param.is_empty())
            {
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
/// `\:` → `;`, `\s` → space, `\\` → `\`, `\r` → CR, `\n` → LF
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
/// `;` → `\:`, space → `\s`, `\` → `\\`, CR → `\r`, LF → `\n`
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let msg = Message::parse("NICK alice").unwrap();
        assert!(msg.tags.is_empty());
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["alice"]);
    }

    #[test]
    fn parse_with_tags() {
        let msg = Message::parse("@content-type=image/jpeg;media-url=https://example.com/img.jpg :alice!a@host PRIVMSG #chan :check this out").unwrap();
        assert_eq!(msg.tags.get("content-type").unwrap(), "image/jpeg");
        assert_eq!(msg.tags.get("media-url").unwrap(), "https://example.com/img.jpg");
        assert_eq!(msg.prefix.as_deref(), Some("alice!a@host"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#chan", "check this out"]);
    }

    #[test]
    fn tag_escaping_roundtrip() {
        let original = "hello world; backslash\\ and\nnewline";
        let escaped = escape_tag_value(original);
        let unescaped = unescape_tag_value(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn parse_tags_with_escapes() {
        let msg = Message::parse("@media-alt=A\\ssunset\\sover\\smountains :bob PRIVMSG #pics :sunset.jpg").unwrap();
        assert_eq!(msg.tags.get("media-alt").unwrap(), "A sunset over mountains");
    }

    #[test]
    fn format_with_tags() {
        let mut tags = HashMap::new();
        tags.insert("content-type".to_string(), "image/jpeg".to_string());
        let msg = Message::with_tags(tags, "PRIVMSG", vec!["#chan", "check this out"]);
        let s = msg.to_string();
        assert!(s.starts_with("@content-type=image/jpeg"));
        assert!(s.contains("PRIVMSG #chan :check this out"));
    }

    #[test]
    fn parse_with_prefix_no_tags() {
        let msg = Message::parse(":server 001 alice :Welcome").unwrap();
        assert!(msg.tags.is_empty());
        assert_eq!(msg.prefix.as_deref(), Some("server"));
        assert_eq!(msg.command, "001");
    }

    #[test]
    fn parse_valueless_tag() {
        let msg = Message::parse("@draft/reply PRIVMSG #chan :text").unwrap();
        assert_eq!(msg.tags.get("draft/reply").unwrap(), "");
    }
}
