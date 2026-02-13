//! Ratatui rendering for the TUI.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::Frame;

#[cfg(feature = "inline-images")]
use crate::app::{ImageState, IMAGE_ROWS};
use crate::app::App;

pub fn draw(frame: &mut Frame, app: &mut App) {
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

    // Overlay: network stats popup
    if app.show_net_popup {
        draw_net_popup(frame, app);
    }
}

fn draw_net_popup(frame: &mut Frame, app: &App) {
    use ratatui::widgets::Clear;

    let area = frame.area();
    // Center a box, 60 wide, 14 tall (or fit to screen)
    let w = 60u16.min(area.width.saturating_sub(4));
    let h = 16u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup_area = Rect::new(x, y, w, h);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let uptime = app.connected_at.map(|t| {
        let d = t.elapsed();
        let secs = d.as_secs();
        format!("{}h {:02}m {:02}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }).unwrap_or_else(|| "—".to_string());

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Transport:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} {}", app.transport.icon(), app.transport.description()),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Server:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.server_addr),
        ]),
        Line::from(vec![
            Span::styled("  State:      ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.connection_state),
        ]),
        Line::from(vec![
            Span::styled("  Uptime:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(&uptime),
        ]),
        Line::from(vec![
            Span::styled("  Nick:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(&app.nick),
        ]),
        Line::from(vec![
            Span::styled("  Auth:       ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.authenticated_did.as_deref().unwrap_or("guest (unauthenticated)")),
        ]),
    ];

    if let Some(ref id) = app.iroh_endpoint_id {
        lines.push(Line::from(vec![
            Span::styled("  Iroh ID:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(&id[..16.min(id.len())], Style::default().fg(Color::Magenta)),
            Span::styled("…", Style::default().fg(Color::DarkGray)),
        ]));
    }

    // E2EE status
    let e2ee_channels: Vec<&String> = app.channel_keys.keys().collect();
    let e2ee_str = if e2ee_channels.is_empty() {
        "none".to_string()
    } else {
        e2ee_channels.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
    };
    lines.push(Line::from(vec![
        Span::styled("  E2EE:       ", Style::default().fg(Color::DarkGray)),
        Span::raw(e2ee_str),
    ]));

    // P2P status
    let p2p_str = if app.p2p_handle.is_some() { "active" } else { "inactive" };
    lines.push(Line::from(vec![
        Span::styled("  P2P DMs:    ", Style::default().fg(Color::DarkGray)),
        Span::raw(p2p_str),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press Esc or /net to close",
        Style::default().fg(Color::DarkGray),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Network Info ")
        .style(Style::default().bg(Color::Black).fg(Color::White))
        .border_style(Style::default().fg(Color::Cyan));

    let popup = Paragraph::new(lines).block(block);
    frame.render_widget(popup, popup_area);
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    use crate::app::Transport;

    // Transport badge: colored background, white bold text
    let badge_bg = match app.transport {
        Transport::Tcp => Color::Red,
        Transport::Tls => Color::Green,
        Transport::WebSocket => Color::Cyan,
        Transport::Iroh => Color::Magenta,
    };

    let auth_str = match &app.authenticated_did {
        Some(did) => format!(" auth:{did}"),
        None => " guest".to_string(),
    };

    let uptime = app.connected_at.map(|t| {
        let d = t.elapsed();
        if d.as_secs() < 60 { format!("{}s", d.as_secs()) }
        else if d.as_secs() < 3600 { format!("{}m", d.as_secs() / 60) }
        else { format!("{}h{}m", d.as_secs() / 3600, (d.as_secs() % 3600) / 60) }
    }).unwrap_or_default();

    let spans = vec![
        Span::styled(
            format!(" {} {} ", app.transport.icon(), app.transport.label()),
            Style::default().bg(badge_bg).fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} | {}{} | {} ",
                app.connection_state, app.nick, auth_str, uptime),
            Style::default().bg(Color::DarkGray).fg(Color::White),
        ),
    ];

    let status = Paragraph::new(Line::from(spans));
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

fn draw_messages(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = {
        let buffer = match app.buffers.get(&app.active_buffer) {
            Some(b) => b,
            None => return,
        };
        match &buffer.topic {
            Some(topic) => format!(" {} — {} ", buffer.name, topic),
            None => format!(" {} ", buffer.name),
        }
    };

    // Draw the block border first, then work inside it
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    #[cfg(feature = "inline-images")]
    let has_picker = app.picker.is_some();
    #[cfg(not(feature = "inline-images"))]
    let has_picker = false;

    let buffer = app.buffers.get(&app.active_buffer).unwrap();
    let inner_height = inner.height as usize;
    let inner_width = inner.width as usize;

    /// Calculate how many terminal rows a message needs when wrapped.
    fn wrapped_height(msg: &crate::app::BufferLine, width: usize) -> usize {
        if width == 0 { return 1; }
        let text_len = if msg.is_system {
            // "HH:MM:SS *** message"
            msg.timestamp.len() + 1 + 4 + msg.text.len()
        } else {
            // "HH:MM:SS <nick> message"
            msg.timestamp.len() + 1 + msg.from.len() + 2 + 1 + msg.text.len()
        };
        (text_len + width - 1) / width  // ceil division
    }

    // Calculate height of each message including wrapping + images
    let msg_heights: Vec<usize> = buffer.messages.iter().map(|msg| {
        #[allow(unused_mut)]
        let mut h = wrapped_height(msg, inner_width);
        #[cfg(feature = "inline-images")]
        if has_picker {
            if let Some(ref url) = msg.image_url {
                let cache = app.image_cache.lock().unwrap();
                if matches!(cache.get(url.as_str()), Some(ImageState::Ready(_))) {
                    h += IMAGE_ROWS as usize;
                }
            }
        }
        let _ = (has_picker, &msg.image_url); // suppress unused warnings
        h
    }).collect();

    let scroll = buffer.scroll as usize;

    // Find the range of messages to display, working backwards from the end
    let mut remaining = inner_height + scroll;
    let mut start_idx = msg_heights.len();
    for (i, &h) in msg_heights.iter().enumerate().rev() {
        if remaining == 0 {
            break;
        }
        start_idx = i;
        remaining = remaining.saturating_sub(h);
    }

    // Skip the scroll offset from the bottom
    let mut visible_msgs: Vec<(usize, usize)> = Vec::new(); // (msg_index, height)
    let mut total_visible: usize = 0;
    for (i, &h) in msg_heights.iter().enumerate().skip(start_idx) {
        visible_msgs.push((i, h));
        total_visible += h;
    }

    // Trim from top if we overshoot
    let mut rows_to_skip_top = if total_visible > inner_height + scroll {
        total_visible - inner_height - scroll
    } else {
        0
    };

    // Render messages top-down within the inner area
    let mut y = inner.y;
    let max_y = inner.y + inner.height;

    // Collect image URLs that need protocol state created
    #[allow(unused_mut, unused_variables)]
    let mut needs_proto: Vec<String> = Vec::new();

    for &(msg_idx, msg_h) in &visible_msgs {
        // Skip messages consumed by top overflow
        if rows_to_skip_top >= msg_h {
            rows_to_skip_top -= msg_h;
            continue;
        }

        if y >= max_y {
            break;
        }

        let msg = &buffer.messages[msg_idx];

        // Render the message with word wrapping
        if y < max_y {
            use ratatui::widgets::Wrap;
            use ratatui::text::Text;

            let text = if msg.is_system {
                Text::from(Line::from(vec![
                    Span::styled(
                        format!("{} ", msg.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("*** {}", msg.text),
                        Style::default().fg(Color::Cyan),
                    ),
                ]))
            } else {
                Text::from(Line::from(vec![
                    Span::styled(
                        format!("{} ", msg.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("<{}> ", msg.from),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(&msg.text),
                ]))
            };

            let h = wrapped_height(msg, inner.width as usize) as u16;
            let rows = h.min(max_y - y);
            let msg_area = Rect::new(inner.x, y, inner.width, rows);
            frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), msg_area);
            y += rows;
        }

        // Render image if present and ready
        #[cfg(feature = "inline-images")]
        if has_picker && y < max_y {
            if let Some(ref url) = msg.image_url {
                let cache = app.image_cache.lock().unwrap();
                if matches!(cache.get(url.as_str()), Some(ImageState::Ready(_))) {
                    let img_h = IMAGE_ROWS.min(max_y - y);
                    needs_proto.push(url.clone());
                    drop(cache);

                    let img_area = Rect::new(inner.x + 2, y, inner.width.saturating_sub(4), img_h);
                    y += img_h;

                    // Create protocol state if needed, then render
                    if !app.image_protos.contains_key(url) {
                        if let Some(ref mut picker) = app.picker {
                            let cache = app.image_cache.lock().unwrap();
                            if let Some(ImageState::Ready(img)) = cache.get(url.as_str()) {
                                let proto = picker.new_resize_protocol(img.clone());
                                drop(cache);
                                app.image_protos.insert(url.clone(), proto);
                            }
                        }
                    }
                    if let Some(proto) = app.image_protos.get_mut(url) {
                        let widget = ratatui_image::StatefulImage::<ratatui_image::protocol::StatefulProtocol>::default();
                        frame.render_stateful_widget(widget, img_area, proto);
                    }
                } else if matches!(cache.get(url.as_str()), Some(ImageState::Loading)) {
                    drop(cache);
                    let loading = Paragraph::new("  ⏳ Loading image...")
                        .style(Style::default().fg(Color::DarkGray));
                    let load_area = Rect::new(inner.x, y, inner.width, 1);
                    frame.render_widget(loading, load_area);
                    y += 1;
                }
            }
        }
    }
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
