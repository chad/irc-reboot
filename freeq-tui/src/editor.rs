//! Line editor with emacs (default) and vi modes.
//!
//! Handles all keybindings for text input, cursor movement, kill ring,
//! word operations, and vi modal editing.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Editing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Emacs,
    Vi,
}

/// Vi sub-mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViMode {
    Insert,
    Normal,
}

/// Result of processing a key event.
pub enum EditAction {
    /// Nothing to do (key was consumed by the editor).
    None,
    /// Submit the current line (Enter pressed).
    Submit,
    /// History up requested.
    HistoryUp,
    /// History down requested.
    HistoryDown,
    /// Tab completion requested.
    Complete,
    /// Next buffer.
    NextBuffer,
    /// Previous buffer.
    PrevBuffer,
    /// Scroll up N lines.
    ScrollUp(u16),
    /// Scroll down N lines.
    ScrollDown(u16),
    /// Quit requested.
    Quit,
}

/// A line editor with emacs and vi keybinding support.
pub struct LineEditor {
    /// Current input text.
    pub text: String,
    /// Byte offset of cursor in text.
    pub cursor: usize,
    /// Kill ring (last killed text, for yank).
    pub kill_ring: String,
    /// Editing mode.
    pub mode: Mode,
    /// Vi sub-mode (only relevant when mode == Vi).
    pub vi_mode: ViMode,
}

impl LineEditor {
    pub fn new(mode: Mode) -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            kill_ring: String::new(),
            mode,
            vi_mode: ViMode::Insert,
        }
    }

    /// Set the text and cursor (for history browsing).
    pub fn set(&mut self, text: String) {
        self.cursor = text.len();
        self.text = text;
        if self.mode == Mode::Vi {
            self.vi_mode = ViMode::Insert;
        }
    }

    /// Take the text, clearing the editor.
    pub fn take(&mut self) -> String {
        self.cursor = 0;
        if self.mode == Mode::Vi {
            self.vi_mode = ViMode::Insert;
        }
        std::mem::take(&mut self.text)
    }

    /// Process a key event. Returns what action the caller should take.
    pub fn handle_key(&mut self, key: KeyEvent) -> EditAction {
        // Ctrl-C / Ctrl-Q always quits
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') | KeyCode::Char('q') => return EditAction::Quit,
                _ => {}
            }
        }

        match self.mode {
            Mode::Emacs => self.handle_emacs(key),
            Mode::Vi => match self.vi_mode {
                ViMode::Insert => self.handle_vi_insert(key),
                ViMode::Normal => self.handle_vi_normal(key),
            },
        }
    }

    /// Is the editor in vi normal mode? (for cursor display)
    pub fn is_vi_normal(&self) -> bool {
        self.mode == Mode::Vi && self.vi_mode == ViMode::Normal
    }

    // ── Emacs mode ──────────────────────────────────────────────────

    fn handle_emacs(&mut self, key: KeyEvent) -> EditAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);

        match key.code {
            KeyCode::Enter => EditAction::Submit,
            KeyCode::Up => EditAction::HistoryUp,
            KeyCode::Down => EditAction::HistoryDown,
            KeyCode::Tab => EditAction::Complete,
            KeyCode::BackTab => EditAction::PrevBuffer,
            KeyCode::PageUp => EditAction::ScrollUp(10),
            KeyCode::PageDown => EditAction::ScrollDown(10),

            // Movement
            KeyCode::Left if ctrl => { self.word_back(); EditAction::None }
            KeyCode::Right if ctrl => { self.word_forward(); EditAction::None }
            KeyCode::Left => { self.cursor_left(); EditAction::None }
            KeyCode::Right => { self.cursor_right(); EditAction::None }
            KeyCode::Home => { self.cursor = 0; EditAction::None }
            KeyCode::End => { self.cursor = self.text.len(); EditAction::None }

            KeyCode::Backspace => { self.backspace(); EditAction::None }
            KeyCode::Delete => { self.delete_char(); EditAction::None }

            KeyCode::Char(c) if ctrl => self.handle_ctrl(c),
            KeyCode::Char(c) if alt => self.handle_alt(c),
            KeyCode::Char(c) => { self.insert(c); EditAction::None }
            _ => EditAction::None,
        }
    }

    fn handle_ctrl(&mut self, c: char) -> EditAction {
        match c {
            'a' => { self.cursor = 0; EditAction::None }
            'e' => { self.cursor = self.text.len(); EditAction::None }
            'f' => { self.cursor_right(); EditAction::None }
            'b' => { self.cursor_left(); EditAction::None }
            'd' => { self.delete_char(); EditAction::None }
            'h' => { self.backspace(); EditAction::None }
            'k' => { self.kill_to_end(); EditAction::None }
            'u' => { self.kill_to_start(); EditAction::None }
            'w' => { self.kill_word_back(); EditAction::None }
            'y' => { self.yank(); EditAction::None }
            't' => { self.transpose(); EditAction::None }
            'l' => EditAction::None, // ignore (would clear screen)
            'n' => EditAction::NextBuffer,
            'p' => EditAction::PrevBuffer,
            _ => EditAction::None,
        }
    }

    fn handle_alt(&mut self, c: char) -> EditAction {
        match c {
            'f' => { self.word_forward(); EditAction::None }
            'b' => { self.word_back(); EditAction::None }
            'd' => { self.kill_word_forward(); EditAction::None }
            'u' => { self.upcase_word(); EditAction::None }
            'l' => { self.downcase_word(); EditAction::None }
            'c' => { self.capitalize_word(); EditAction::None }
            't' => { self.transpose_words(); EditAction::None }
            'n' => EditAction::NextBuffer,
            'p' | 'h' => EditAction::PrevBuffer,
            _ => EditAction::None,
        }
    }

    // ── Vi insert mode ──────────────────────────────────────────────

    fn handle_vi_insert(&mut self, key: KeyEvent) -> EditAction {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Esc => {
                self.vi_mode = ViMode::Normal;
                // Back up one char like vi does
                if self.cursor > 0 {
                    self.cursor_left();
                }
                EditAction::None
            }
            KeyCode::Enter => EditAction::Submit,
            KeyCode::Up => EditAction::HistoryUp,
            KeyCode::Down => EditAction::HistoryDown,
            KeyCode::Tab => EditAction::Complete,
            KeyCode::BackTab => EditAction::PrevBuffer,
            KeyCode::PageUp => EditAction::ScrollUp(10),
            KeyCode::PageDown => EditAction::ScrollDown(10),
            KeyCode::Left => { self.cursor_left(); EditAction::None }
            KeyCode::Right => { self.cursor_right(); EditAction::None }
            KeyCode::Home => { self.cursor = 0; EditAction::None }
            KeyCode::End => { self.cursor = self.text.len(); EditAction::None }
            KeyCode::Backspace => { self.backspace(); EditAction::None }
            KeyCode::Delete => { self.delete_char(); EditAction::None }
            KeyCode::Char(c) if ctrl => {
                match c {
                    'w' => { self.kill_word_back(); EditAction::None }
                    'u' => { self.kill_to_start(); EditAction::None }
                    'h' => { self.backspace(); EditAction::None }
                    'n' => EditAction::NextBuffer,
                    'p' => EditAction::PrevBuffer,
                    _ => EditAction::None,
                }
            }
            KeyCode::Char(c) => { self.insert(c); EditAction::None }
            _ => EditAction::None,
        }
    }

    // ── Vi normal mode ──────────────────────────────────────────────

    fn handle_vi_normal(&mut self, key: KeyEvent) -> EditAction {
        match key.code {
            // Mode switching
            KeyCode::Char('i') => { self.vi_mode = ViMode::Insert; EditAction::None }
            KeyCode::Char('a') => {
                self.vi_mode = ViMode::Insert;
                self.cursor_right();
                EditAction::None
            }
            KeyCode::Char('I') => {
                self.vi_mode = ViMode::Insert;
                self.cursor = 0;
                EditAction::None
            }
            KeyCode::Char('A') => {
                self.vi_mode = ViMode::Insert;
                self.cursor = self.text.len();
                EditAction::None
            }

            // Movement
            KeyCode::Char('h') | KeyCode::Left => { self.cursor_left(); EditAction::None }
            KeyCode::Char('l') | KeyCode::Right => { self.cursor_right(); EditAction::None }
            KeyCode::Char('0') | KeyCode::Home => { self.cursor = 0; EditAction::None }
            KeyCode::Char('$') | KeyCode::End => {
                if !self.text.is_empty() {
                    self.cursor = self.prev_char_boundary(self.text.len());
                }
                EditAction::None
            }
            KeyCode::Char('^') => {
                self.cursor = self.text.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                EditAction::None
            }
            KeyCode::Char('w') => { self.word_forward(); EditAction::None }
            KeyCode::Char('b') => { self.word_back(); EditAction::None }
            KeyCode::Char('e') => { self.word_end(); EditAction::None }

            // Editing
            KeyCode::Char('x') | KeyCode::Delete => { self.delete_char(); EditAction::None }
            KeyCode::Char('X') => { self.backspace(); EditAction::None }
            KeyCode::Char('D') => { self.kill_to_end(); EditAction::None }
            KeyCode::Char('C') => {
                self.kill_to_end();
                self.vi_mode = ViMode::Insert;
                EditAction::None
            }
            KeyCode::Char('S') | KeyCode::Char('c') if matches!(key.code, KeyCode::Char('S')) => {
                self.text.clear();
                self.cursor = 0;
                self.vi_mode = ViMode::Insert;
                EditAction::None
            }
            KeyCode::Char('s') => {
                self.delete_char();
                self.vi_mode = ViMode::Insert;
                EditAction::None
            }
            KeyCode::Char('p') => { self.paste_after(); EditAction::None }
            KeyCode::Char('P') => { self.yank(); EditAction::None }

            // History
            KeyCode::Char('k') | KeyCode::Up => EditAction::HistoryUp,
            KeyCode::Char('j') | KeyCode::Down => EditAction::HistoryDown,

            // Scroll
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => EditAction::ScrollUp(10),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => EditAction::ScrollDown(10),
            KeyCode::PageUp => EditAction::ScrollUp(10),
            KeyCode::PageDown => EditAction::ScrollDown(10),

            // Buffer switching
            KeyCode::Tab => EditAction::NextBuffer,
            KeyCode::BackTab => EditAction::PrevBuffer,

            KeyCode::Enter => {
                self.vi_mode = ViMode::Insert;
                EditAction::Submit
            }

            _ => EditAction::None,
        }
    }

    // ── Primitive operations ────────────────────────────────────────

    fn insert(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            let prev = self.prev_char_boundary(self.cursor);
            self.text.drain(prev..self.cursor);
            self.cursor = prev;
        }
    }

    fn delete_char(&mut self) {
        if self.cursor < self.text.len() {
            let next = self.next_char_boundary(self.cursor);
            self.kill_ring = self.text[self.cursor..next].to_string();
            self.text.drain(self.cursor..next);
        }
    }

    fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.prev_char_boundary(self.cursor);
        }
    }

    fn cursor_right(&mut self) {
        if self.cursor < self.text.len() {
            self.cursor = self.next_char_boundary(self.cursor);
        }
    }

    fn kill_to_end(&mut self) {
        self.kill_ring = self.text[self.cursor..].to_string();
        self.text.truncate(self.cursor);
    }

    fn kill_to_start(&mut self) {
        self.kill_ring = self.text[..self.cursor].to_string();
        self.text.drain(..self.cursor);
        self.cursor = 0;
    }

    fn kill_word_back(&mut self) {
        let start = self.find_word_start_back();
        self.kill_ring = self.text[start..self.cursor].to_string();
        self.text.drain(start..self.cursor);
        self.cursor = start;
    }

    fn kill_word_forward(&mut self) {
        let end = self.find_word_end_forward();
        self.kill_ring = self.text[self.cursor..end].to_string();
        self.text.drain(self.cursor..end);
    }

    fn yank(&mut self) {
        let paste = self.kill_ring.clone();
        self.text.insert_str(self.cursor, &paste);
        self.cursor += paste.len();
    }

    fn paste_after(&mut self) {
        // Vi 'p': paste after cursor
        let after = self.next_char_boundary(self.cursor);
        let paste = self.kill_ring.clone();
        self.text.insert_str(after, &paste);
        self.cursor = after + paste.len().saturating_sub(1);
    }

    fn transpose(&mut self) {
        // Ctrl-T: swap char before cursor with char at cursor
        if self.cursor == 0 || self.text.len() < 2 {
            return;
        }
        let pos = if self.cursor >= self.text.len() {
            self.prev_char_boundary(self.text.len())
        } else {
            self.cursor
        };
        let prev_pos = self.prev_char_boundary(pos);
        let c1: String = self.text[prev_pos..pos].to_string();
        let next_pos = self.next_char_boundary(pos);
        let c2: String = self.text[pos..next_pos].to_string();
        self.text.replace_range(prev_pos..next_pos, &format!("{c2}{c1}"));
        self.cursor = next_pos;
    }

    fn word_forward(&mut self) {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        // Skip current word
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() { i += 1; }
        // Skip whitespace
        while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
        self.cursor = i;
    }

    fn word_back(&mut self) {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        // Skip whitespace before
        while i > 0 && bytes[i - 1].is_ascii_whitespace() { i -= 1; }
        // Skip word
        while i > 0 && !bytes[i - 1].is_ascii_whitespace() { i -= 1; }
        self.cursor = i;
    }

    fn word_end(&mut self) {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        if i < bytes.len() { i += 1; }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() { i += 1; }
        i = i.saturating_sub(1);
        self.cursor = i;
    }

    fn upcase_word(&mut self) {
        let end = self.find_word_end_forward();
        let word: String = self.text[self.cursor..end].to_uppercase();
        self.text.replace_range(self.cursor..end, &word);
        self.cursor += word.len();
    }

    fn downcase_word(&mut self) {
        let end = self.find_word_end_forward();
        let word: String = self.text[self.cursor..end].to_lowercase();
        self.text.replace_range(self.cursor..end, &word);
        self.cursor += word.len();
    }

    fn capitalize_word(&mut self) {
        let end = self.find_word_end_forward();
        if self.cursor < end {
            let mut chars = self.text[self.cursor..end].chars();
            if let Some(first) = chars.next() {
                let word: String = first.to_uppercase().chain(chars.map(|c| c.to_lowercase().next().unwrap_or(c))).collect();
                self.text.replace_range(self.cursor..end, &word);
                self.cursor += word.len();
            }
        }
    }

    fn transpose_words(&mut self) {
        // Simple version: swap the two words around cursor
        let end2 = self.find_word_end_forward();
        let start2 = {
            let bytes = self.text.as_bytes();
            let mut i = self.cursor;
            while i > 0 && bytes[i - 1].is_ascii_whitespace() { i -= 1; }
            while i > 0 && !bytes[i - 1].is_ascii_whitespace() { i -= 1; }
            i
        };
        let start1 = {
            let bytes = self.text.as_bytes();
            let mut i = start2;
            while i > 0 && bytes[i - 1].is_ascii_whitespace() { i -= 1; }
            while i > 0 && !bytes[i - 1].is_ascii_whitespace() { i -= 1; }
            i
        };
        if start1 < start2 && start2 <= self.cursor && self.cursor <= end2 {
            let word1 = self.text[start1..start2].trim().to_string();
            let space = self.text[start1 + word1.len()..start2].to_string();
            let word2 = self.text[start2..end2].to_string();
            self.text.replace_range(start1..end2, &format!("{word2}{space}{word1}"));
            self.cursor = start1 + word2.len() + space.len() + word1.len();
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn find_word_start_back(&self) -> usize {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        while i > 0 && bytes[i - 1].is_ascii_whitespace() { i -= 1; }
        while i > 0 && !bytes[i - 1].is_ascii_whitespace() { i -= 1; }
        i
    }

    fn find_word_end_forward(&self) -> usize {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() { i += 1; }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() { i += 1; }
        i
    }

    fn prev_char_boundary(&self, pos: usize) -> usize {
        let mut i = pos.saturating_sub(1);
        while i > 0 && !self.text.is_char_boundary(i) { i -= 1; }
        i
    }

    fn next_char_boundary(&self, pos: usize) -> usize {
        let mut i = pos + 1;
        while i < self.text.len() && !self.text.is_char_boundary(i) { i += 1; }
        i.min(self.text.len())
    }
}
