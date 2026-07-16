mod app;
mod input;
mod ui;

use std::io;
use std::path::Path;

use anyhow::{Context, Result};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use self::app::{App, Screen};
use self::input::handle_event;
use self::ui::draw;

pub fn run(vault_path: &Path) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!(
            "vault not found at {}. Run `credman init` or `credman restore` first.",
            vault_path.display()
        );
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, vault_path);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, vault_path: &Path) -> Result<()> {
    let mut app = App::new(vault_path.to_path_buf());

    loop {
        terminal.draw(|f| draw(f, &app))?;
        if handle_event(&mut app)? {
            break;
        }
        if app.screen == Screen::Quit {
            break;
        }
    }

    if let Some(ref mut vault) = app.vault {
        vault.persist().context("failed to save vault on exit")?;
    }
    Ok(())
}
