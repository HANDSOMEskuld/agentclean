use agentclean::{
    model::{Finding, FindingExplanation, Risk, ScanReport, ScanStatus},
    tui::{render, App, Screen},
};
use ratatui::{backend::TestBackend, Terminal};
use std::path::PathBuf;

fn report() -> ScanReport {
    ScanReport {
        root: PathBuf::from("/workspace/demo"),
        files: vec![Finding {
            path: PathBuf::from("/workspace/demo/cache.bin"),
            bytes: 42,
            apparent_bytes: 42,
            allocated_bytes: 42,
            reclaimable_allocated_bytes: 42,
            modified_secs: 1_700_000_000,
            age_secs: Some(1),
            risk: Risk::Caution,
            rule_id: Some("cache".into()),
            kind: "file".into(),
            explanation: FindingExplanation::default(),
        }],
        errors: vec!["permission denied".into()],
        scanned_bytes: 42,
        scanned_files: 1,
        status: ScanStatus::Complete,
        duration_ms: 1,
        scanned_apparent_bytes: 42,
        scanned_allocated_bytes: 42,
    }
}

#[test]
fn app_starts_on_overview_and_uses_report_values() {
    let app = App::new(report());
    assert_eq!(app.screen(), Screen::Overview);
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect::<String>();
    assert!(text.contains("/workspace/demo"));
    assert!(text.contains("42"));
    assert!(text.contains("permission denied"));
}

#[test]
fn navigation_changes_tabs_and_selects_candidate_detail_without_mutation() {
    let mut app = App::new(report());
    app.handle_key(crossterm::event::KeyCode::Tab);
    assert_eq!(app.screen(), Screen::Candidates);
    app.handle_key(crossterm::event::KeyCode::Down);
    app.handle_key(crossterm::event::KeyCode::Enter);
    assert_eq!(app.screen(), Screen::Detail);
    assert_eq!(
        app.selected_finding().unwrap().path,
        PathBuf::from("/workspace/demo/cache.bin")
    );
    app.handle_key(crossterm::event::KeyCode::Esc);
    assert_eq!(app.screen(), Screen::Candidates);
}

#[test]
fn quit_keys_are_reported_and_navigation_is_bounded() {
    let mut app = App::new(report());
    assert!(!app.handle_key(crossterm::event::KeyCode::Down));
    assert!(!app.handle_key(crossterm::event::KeyCode::Up));
    assert!(app.handle_key(crossterm::event::KeyCode::Char('q')));
}
