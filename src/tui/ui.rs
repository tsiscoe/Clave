//! Ratatui v0.30+ layout and ANSI/OSC escape-sanitized rendering for Loom.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::tui::{ActivePane, LoomTuiApp};

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// untrusted log/file strings into the terminal buffer (`CWE-150`).
pub fn sanitize_terminal_str(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

/// Render the 3-pane Loom TUI (Top-Left: Raw Input, Top-Right: Woven Sterile Output,
/// Bottom: Encrypted Token Mapping Ledger).
pub fn render(frame: &mut Frame, app: &LoomTuiApp) {
    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(52),
            Constraint::Percentage(42),
            Constraint::Length(2),
        ])
        .split(frame.area());

    // 1. Header Masthead
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " LOOM v0.1.0 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "BIDIRECTIONAL FORMAT-PRESERVING CRYPTOGRAPHIC SCRUBBER",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, root_chunks[0]);

    // 2. Side-by-Side Diff Panes (Raw Input vs. Woven Output)
    let diff_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root_chunks[1]);

    let raw_border_style = if app.active_pane == ActivePane::RawInput {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let woven_border_style = if app.active_pane == ActivePane::WovenOutput {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let clean_raw = sanitize_terminal_str(&app.raw_text);
    let raw_pane = Paragraph::new(clean_raw)
        .scroll((app.scroll_offset, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" [01] RAW INPUT (SENSITIVE) ")
                .borders(Borders::ALL)
                .border_style(raw_border_style),
        );
    frame.render_widget(raw_pane, diff_chunks[0]);

    let clean_woven = sanitize_terminal_str(&app.woven_text);
    let woven_pane = Paragraph::new(clean_woven)
        .scroll((app.scroll_offset, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" [02] WOVEN OUTPUT (STERILE / SAFE FOR LLM & GIT) ")
                .borders(Borders::ALL)
                .border_style(woven_border_style),
        );
    frame.render_widget(woven_pane, diff_chunks[1]);

    // 3. Bottom Ledger Table
    let table_border_style = if app.active_pane == ActivePane::MappingTable {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let header_cells = [
        "CATEGORY",
        "SYNTHETIC TOKEN (PUBLIC)",
        "REAL VALUE (AEAD VAULT)",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let table_header = Row::new(header_cells).height(1);

    let rows = app.mappings.iter().enumerate().map(|(idx, m)| {
        let style = if idx == app.selected_mapping {
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(sanitize_terminal_str(&m.category)),
            Cell::from(sanitize_terminal_str(&m.synthetic_value)),
            Cell::from(sanitize_terminal_str(&m.real_value)),
        ])
        .style(style)
    });

    let widths = [
        Constraint::Length(12),
        Constraint::Percentage(44),
        Constraint::Percentage(44),
    ];

    let mapping_table = Table::new(rows, widths).header(table_header).block(
        Block::default()
            .title(format!(
                " [03] ENCRYPTED BIDIRECTIONAL LEDGER ({} MAPPINGS) ",
                app.mappings.len()
            ))
            .borders(Borders::ALL)
            .border_style(table_border_style),
    );
    frame.render_widget(mapping_table, root_chunks[2]);

    // 4. Footer Status Bar
    let status = Paragraph::new(sanitize_terminal_str(&app.status_message))
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(status, root_chunks[3]);
}
