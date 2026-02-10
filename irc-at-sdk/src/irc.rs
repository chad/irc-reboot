//! IRC message types — shared between SDK and server.
//! This is a minimal parser/formatter for IRC protocol lines.

use std::fmt;

/// A parsed IRC message.
#[derive(Debug, Clone)]
pub struct Message {
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
}

impl Message {
    /// Parse a raw IRC line.
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return None;
        }

        let mut rest = line;
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
            prefix,
            command,
            params,
        })
    }

    pub fn new(command: &str, params: Vec<&str>) -> Self {
        Self {
            prefix: None,
            command: command.to_string(),
            params: params.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
