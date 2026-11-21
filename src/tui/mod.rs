//! Ratatui v0.30+ interactive side-by-side Raw vs. Woven diff viewer & token mapping inspector.

pub mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::store::TokenMapping;

/// Active focus pane in the Loom TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    RawInput,
    WovenOutput,
    MappingTable,
}

/// Application state for the Ratatui diff & token ledger viewer.
pub struct LoomTuiApp {
    pub raw_text: String,
    pub woven_text: String,
    pub mappings: Vec<TokenMapping>,
    pub selected_mapping: usize,
    pub scroll_offset: u16,
    pub active_pane: ActivePane,
    pub status_message: String,
    pub should_quit: bool,
}

impl LoomTuiApp {
    /// Construct a new `LoomTuiApp` instance.
    pub fn new(raw_text: String, woven_text: String, mappings: Vec<TokenMapping>) -> Self {
        let count = mappings.len();
        Self {
            raw_text,
            woven_text,
            mappings,
            selected_mapping: 0,
            scroll_offset: 0,
            active_pane: ActivePane::MappingTable,
            status_message: format!(
                "Loaded {count} encrypted token mappings. [Tab] Switch Pane  [j/k] Navigate  [c] Copy Woven  [q] Quit"
            ),
            should_quit: false,
        }
    }

    /// Cycle focus to the next pane.
    pub fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::RawInput => ActivePane::WovenOutput,
            ActivePane::WovenOutput => ActivePane::MappingTable,
            ActivePane::MappingTable => ActivePane::RawInput,
        };
    }

    /// Move selection or scroll down.
    pub fn move_down(&mut self) {
        match self.active_pane {
            ActivePane::MappingTable => {
                if !self.mappings.is_empty() {
                    self.selected_mapping = (self.selected_mapping + 1) % self.mappings.len();
                }
            }
            ActivePane::RawInput | ActivePane::WovenOutput => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
        }
    }

    /// Move selection or scroll up.
    pub fn move_up(&mut self) {
        match self.active_pane {
            ActivePane::MappingTable => {
                if !self.mappings.is_empty() {
                    if self.selected_mapping == 0 {
                        self.selected_mapping = self.mappings.len() - 1;
                    } else {
                        self.selected_mapping -= 1;
                    }
                }
            }
            ActivePane::RawInput | ActivePane::WovenOutput => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
        }
    }
}

/// Launch the interactive Ratatui terminal UI.
pub fn run_interactive_tui(mut app: LoomTuiApp) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut LoomTuiApp,
) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::render(frame, app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.should_quit = true;
                }
                KeyCode::Tab => app.next_pane(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                KeyCode::Char('c') => {
                    if let Ok(mut cb) = arboard::Clipboard::new()
                        && cb.set_text(app.woven_text.clone()).is_ok()
                    {
                        app.status_message =
                            "Copied woven (sterile) text to system clipboard.".to_string();
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
