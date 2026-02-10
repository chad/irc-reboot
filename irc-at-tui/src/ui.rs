//! Ratatui rendering for the TUI.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::Frame;

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Length(1), // tab bar
            Constraint::Min(3),   // message + nicklist area
            Constraint::Length(3), // input
        ])
        .split(frame.area());

    draw_status_bar(frame, app, chunks[0]);
    draw_tab_bar(frame, app, chunks[1]);

    // If in a channel, show nick list sidebar
    let is_channel = app.active_buffer.starts_with('#') || app.active_buffer.starts_with('&');
    if is_channel {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Min(20),       // messages
                Constraint::Length(18),     // nick list
            ])
            .split(chunks[2]);
        draw_messages(frame, app, cols[0]);
        draw_nicklist(frame, app, cols[1]);
    } else {
        draw_messages(frame, app, chunks[2]);
    }

    draw_input(frame, app, chunks[3]);
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let auth_str = match &app.authenticated_did {
        Some(did) => format!(" | auth: {did}"),
        None => " | guest".to_string(),
    };

    let status_text = format!(
        " [{}] nick: {}{}",
        app.connection_state, app.nick, auth_str
    );

    let status = Paragraph::new(status_text)
        .style(Style::default().bg(Color::Blue).fg(Color::White));
    frame.render_widget(status, area);
}

fn draw_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let names = app.buffer_names();
    let active_idx = names
        .iter()
        .position(|n| n == &app.active_buffer)
        .unwrap_or(0);

    let titles: Vec<Line> = names.iter().map(|n| Line::from(n.as_str())).collect();

    let tabs = Tabs::new(titles)
        .select(active_idx)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider("|");

    frame.render_widget(tabs, area);
}

fn draw_messages(frame: &mut Frame, app: &App, area: Rect) {
    let buffer = match app.buffers.get(&app.active_buffer) {
        Some(b) => b,
        None => return,
    };

    let inner_height = area.height.saturating_sub(2) as usize;
    let total = buffer.messages.len();

    // Calculate visible range
    let scroll = buffer.scroll as usize;
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(inner_height);

    let lines: Vec<Line> = buffer.messages
        .iter()
        .skip(start)
        .take(end - start)
        .map(|msg| {
            if msg.is_system {
                Line::from(vec![
                    Span::styled(
                        format!("{} ", msg.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("*** {}", msg.text),
                        Style::default().fg(Color::Cyan),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("{} ", msg.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("<{}> ", msg.from),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(&msg.text),
                ])
            }
        })
        .collect();

    let title = match &buffer.topic {
        Some(topic) => format!(" {} — {} ", buffer.name, topic),
        None => format!(" {} ", buffer.name),
    };
    let messages = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false });

    frame.render_widget(messages, area);
}

fn draw_nicklist(frame: &mut Frame, app: &App, area: Rect) {
    let buffer = match app.buffers.get(&app.active_buffer) {
        Some(b) => b,
        None => return,
    };

    let inner_height = area.height.saturating_sub(2) as usize;

    // Sort nicks: ops (@) first, then voiced (+), then regular
    let mut nicks = buffer.nicks.clone();
    nicks.sort_by(|a, b| {
        let rank = |n: &str| -> u8 {
            if n.starts_with('@') { 0 }
            else if n.starts_with('+') { 1 }
            else { 2 }
        };
        rank(a).cmp(&rank(b)).then(a.cmp(b))
    });

    let lines: Vec<Line> = nicks
        .iter()
        .take(inner_height)
        .map(|n| {
            let (prefix, name) = if n.starts_with('@') || n.starts_with('+') {
                (&n[..1], &n[1..])
            } else {
                ("", n.as_str())
            };
            let prefix_color = if prefix == "@" { Color::Yellow } else { Color::Cyan };
            Line::from(vec![
                Span::styled(prefix, Style::default().fg(prefix_color).add_modifier(Modifier::BOLD)),
                Span::raw(name),
            ])
        })
        .collect();

    let title = format!(" {} ", nicks.len());
    let nicklist = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(nicklist, area);
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let title = if app.editor.is_vi_normal() {
        " Input [NORMAL] "
    } else {
        " Input "
    };
    let input = Paragraph::new(app.editor.text.as_str())
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(input, area);

    // Place cursor
    let cursor_x = area.x + 1 + app.editor.cursor as u16;
    let cursor_y = area.y + 1;
    frame.set_cursor_position((cursor_x, cursor_y));
}
