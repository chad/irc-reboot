//! Application state for the TUI.

use std::collections::{BTreeMap, VecDeque};

use crate::editor::{LineEditor, Mode};

/// Maximum number of messages to keep per buffer.
const MAX_MESSAGES: usize = 1000;

/// A single line in a message buffer.
#[derive(Debug, Clone)]
pub struct BufferLine {
    pub timestamp: String,
    pub from: String,
    pub text: String,
    pub is_system: bool,
}

/// A named message buffer (channel, PM, or status).
#[derive(Debug)]
pub struct Buffer {
    pub name: String,
    pub messages: VecDeque<BufferLine>,
    pub nicks: Vec<String>,
    /// Channel topic, if set.
    pub topic: Option<String>,
    /// Scroll offset from the bottom (0 = at bottom).
    pub scroll: u16,
}

impl Buffer {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            messages: VecDeque::new(),
            nicks: Vec::new(),
            topic: None,
            scroll: 0,
        }
    }

    pub fn push(&mut self, line: BufferLine) {
        self.messages.push_back(line);
        if self.messages.len() > MAX_MESSAGES {
            self.messages.pop_front();
        }
        // Auto-scroll to bottom when new message arrives
        self.scroll = 0;
    }

    pub fn push_system(&mut self, text: &str) {
        self.push(BufferLine {
            timestamp: now_str(),
            from: String::new(),
            text: text.to_string(),
            is_system: true,
        });
    }
}

/// Top-level application state.
pub struct App {
    /// Named buffers, keyed by lowercase name. "status" is always present.
    pub buffers: BTreeMap<String, Buffer>,
    /// Currently active buffer key.
    pub active_buffer: String,
    /// Line editor (handles input, cursor, emacs/vi keybindings).
    pub editor: LineEditor,
    /// Connection state display.
    pub connection_state: String,
    /// Authenticated DID (if any).
    pub authenticated_did: Option<String>,
    /// Our nick.
    pub nick: String,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Input history (most recent last).
    pub history: Vec<String>,
    /// Current position in history (None = not browsing).
    pub history_pos: Option<usize>,
    /// Saved input line when browsing history.
    pub history_saved: String,
}

impl App {
    pub fn new(nick: &str, vi_mode: bool) -> Self {
        let mut buffers = BTreeMap::new();
        let mut status = Buffer::new("status");
        let mode_name = if vi_mode { "vi" } else { "emacs" };
        status.push_system(&format!("Welcome to irc-at-tui ({mode_name} mode). Type /help for commands."));
        buffers.insert("status".to_string(), status);

        let mode = if vi_mode { Mode::Vi } else { Mode::Emacs };

        Self {
            buffers,
            active_buffer: "status".to_string(),
            editor: LineEditor::new(mode),
            connection_state: "connecting".to_string(),
            authenticated_did: None,
            nick: nick.to_string(),
            should_quit: false,
            history: Vec::new(),
            history_pos: None,
            history_saved: String::new(),
        }
    }

    /// Get or create a buffer.
    pub fn buffer_mut(&mut self, name: &str) -> &mut Buffer {
        let key = name.to_lowercase();
        self.buffers
            .entry(key)
            .or_insert_with(|| Buffer::new(name))
    }

    /// Push a system message to the status buffer.
    pub fn status_msg(&mut self, text: &str) {
        self.buffer_mut("status").push_system(text);
    }

    /// Push a chat message to the appropriate buffer.
    pub fn chat_msg(&mut self, target: &str, from: &str, text: &str) {
        // If it's a PM to us, use the sender's nick as the buffer
        let buffer_name = if !target.starts_with('#') && !target.starts_with('&') {
            if from == self.nick {
                target.to_string()
            } else {
                from.to_string()
            }
        } else {
            target.to_string()
        };

        self.buffer_mut(&buffer_name).push(BufferLine {
            timestamp: now_str(),
            from: from.to_string(),
            text: text.to_string(),
            is_system: false,
        });
    }

    /// Switch to the next buffer.
    pub fn next_buffer(&mut self) {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        if let Some(pos) = keys.iter().position(|k| k == &self.active_buffer) {
            let next = (pos + 1) % keys.len();
            self.active_buffer = keys[next].clone();
        }
    }

    /// Switch to the previous buffer.
    pub fn prev_buffer(&mut self) {
        let keys: Vec<String> = self.buffers.keys().cloned().collect();
        if let Some(pos) = keys.iter().position(|k| k == &self.active_buffer) {
            let prev = if pos == 0 { keys.len() - 1 } else { pos - 1 };
            self.active_buffer = keys[prev].clone();
        }
    }

    /// Get the ordered list of buffer names for the tab bar.
    pub fn buffer_names(&self) -> Vec<String> {
        self.buffers.keys().cloned().collect()
    }

    /// Take and clear the input line, pushing it to history.
    pub fn input_take(&mut self) -> String {
        self.history_pos = None;
        let line = self.editor.take();
        if !line.is_empty() {
            self.history.push(line.clone());
        }
        line
    }

    /// Browse up in input history.
    pub fn history_up(&mut self) {
        if self.history.is_empty() {
            return;
        }
        match self.history_pos {
            None => {
                self.history_saved = self.editor.text.clone();
                self.history_pos = Some(self.history.len() - 1);
            }
            Some(pos) if pos > 0 => {
                self.history_pos = Some(pos - 1);
            }
            _ => return,
        }
        let pos = self.history_pos.unwrap();
        self.editor.set(self.history[pos].clone());
    }

    /// Browse down in input history.
    pub fn history_down(&mut self) {
        if let Some(pos) = self.history_pos {
            if pos + 1 < self.history.len() {
                self.history_pos = Some(pos + 1);
                self.editor.set(self.history[pos + 1].clone());
            } else {
                self.history_pos = None;
                let saved = std::mem::take(&mut self.history_saved);
                self.editor.set(saved);
            }
        }
    }
}

fn now_str() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
