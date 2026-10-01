use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::stdout;

use crate::model::{Finding, Risk, ScanReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Candidates,
    Detail,
}

#[derive(Debug, Clone)]
pub struct App {
    report: ScanReport,
    screen: Screen,
    selected: usize,
}

impl App {
    pub fn new(report: ScanReport) -> Self {
        Self {
            report,
            screen: Screen::Overview,
            selected: 0,
        }
    }

    pub fn screen(&self) -> Screen {
        self.screen
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.report.files.get(self.selected)
    }

    /// Returns true when the event requests application exit.
    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') => true,
            KeyCode::Esc if self.screen == Screen::Detail => {
                self.screen = Screen::Candidates;
                false
            }
            KeyCode::Esc => true,
            KeyCode::Tab => {
                self.screen = match self.screen {
                    Screen::Overview => Screen::Candidates,
                    Screen::Candidates => Screen::Detail,
                    Screen::Detail => Screen::Overview,
                };
                false
            }
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                false
            }
            KeyCode::Down => {
                if !self.report.files.is_empty() {
                    self.selected = (self.selected + 1).min(self.report.files.len() - 1);
                }
                false
            }
            KeyCode::Enter
                if self.screen == Screen::Candidates && !self.report.files.is_empty() =>
            {
                self.screen = Screen::Detail;
                false
            }
            _ => false,
        }
    }
}

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(frame.area());
    let title = match app.screen {
        Screen::Overview => "Overview",
        Screen::Candidates => "Candidates",
        Screen::Detail => "Candidate detail",
    };
    let body = match app.screen {
        Screen::Overview => overview(app),
        Screen::Candidates => candidates(app),
        Screen::Detail => detail(app),
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new("Tab: next view  ↑/↓: select  Enter: detail  Esc/q: quit (read-only)"),
        chunks[1],
    );
}

fn overview(app: &App) -> Text<'static> {
    let r = &app.report;
    let mut lines = vec![
        Line::from(format!("Root: {}", r.root.display())),
        Line::from(format!("Scanned files: {}", r.scanned_files)),
        Line::from(format!("Scanned bytes: {}", r.scanned_bytes)),
        Line::from(format!("Report findings: {}", r.files.len())),
        Line::from(format!("Scan errors: {}", r.errors.len())),
        Line::from(""),
        Line::from("This interface only displays the supplied report. It does not delete, move, or modify files."),
        Line::from(if r.errors.is_empty() { "No scan errors reported." } else { "Scan errors:" }),
    ];
    lines.extend(
        r.errors
            .iter()
            .map(|error| Line::from(format!("  {error}"))),
    );
    Text::from(lines)
}

fn candidates(app: &App) -> Text<'static> {
    if app.report.files.is_empty() {
        return Text::from("No findings in supplied report.");
    }
    Text::from(
        app.report
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let marker = if i == app.selected { ">" } else { " " };
                Line::from(vec![
                    Span::raw(format!("{marker} ")),
                    Span::styled(format!("{:?}", f.risk), risk_style(f.risk)),
                    Span::raw(format!("  {} bytes  {}", f.bytes, f.path.display())),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

fn detail(app: &App) -> Text<'static> {
    let Some(f) = app.selected_finding() else {
        return Text::from("No candidate selected.");
    };
    Text::from(vec![
        Line::from(format!("Path: {}", f.path.display())),
        Line::from(format!("Kind: {}", f.kind)),
        Line::from(format!("Bytes: {}", f.bytes)),
        Line::from(format!("Modified (Unix seconds): {}", f.modified_secs)),
        Line::from(format!("Risk: {:?}", f.risk)),
        Line::from(format!("Rule: {}", f.rule_id.as_deref().unwrap_or("none"))),
        Line::from(""),
        Line::from("Read-only detail; no action is available here."),
    ])
}

fn risk_style(risk: Risk) -> Style {
    Style::default().fg(match risk {
        Risk::Safe => Color::Green,
        Risk::Caution => Color::Yellow,
        Risk::Dangerous => Color::Red,
        Risk::Protected => Color::Magenta,
        Risk::Unknown => Color::Gray,
    })
}

pub fn run(report: ScanReport) -> Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(report);
    let result = loop {
        terminal.draw(|frame| render(frame, &app))?;
        if event::poll(std::time::Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key.code) {
                    break Ok(());
                }
            }
        }
    };
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

pub fn run_empty() -> Result<()> {
    run(ScanReport::default())
}

#[allow(dead_code)]
fn _area(_: Rect) {}
