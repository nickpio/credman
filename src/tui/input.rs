use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::{App, Screen};

/// Returns true when the app should quit.
pub fn handle_event(app: &mut App) -> Result<bool> {
    if !event::poll(std::time::Duration::from_millis(200))? {
        return Ok(false);
    }
    let Event::Key(key) = event::read()? else {
        return Ok(false);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.screen = Screen::Quit;
        return Ok(true);
    }

    match app.screen {
        Screen::Unlock => handle_unlock(app, key),
        Screen::Main => handle_main(app, key.code),
        Screen::Add | Screen::Edit => handle_form(app, key.code),
        Screen::ConfirmDelete => handle_confirm(app, key.code),
        Screen::Quit => return Ok(true),
    }
    Ok(app.screen == Screen::Quit)
}

fn handle_unlock(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
        app.show_seed = !app.show_seed;
        return;
    }

    match key.code {
        KeyCode::Esc => app.screen = Screen::Quit,
        KeyCode::Enter => app.try_unlock(),
        KeyCode::Backspace => {
            app.seed_input.pop();
            app.unlock_error = None;
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.seed_input.push(c);
            app.unlock_error = None;
        }
        _ => {}
    }
}

fn handle_main(app: &mut App, code: KeyCode) {
    if app.filtering {
        match code {
            KeyCode::Esc => {
                app.filtering = false;
                app.filter.clear();
                app.recompute_filter();
                app.status = "Filter cleared".into();
            }
            KeyCode::Enter => {
                app.filtering = false;
                app.status = format!("Filter: {}", app.filter);
            }
            KeyCode::Backspace => {
                app.filter.pop();
                app.recompute_filter();
            }
            KeyCode::Char(c) if !c.is_control() => {
                app.filter.push(c);
                app.recompute_filter();
            }
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.screen = Screen::Quit,
        KeyCode::Char('/') => {
            app.filtering = true;
            app.status = "Type to filter, Enter done, Esc clear".into();
        }
        KeyCode::Char('j') | KeyCode::Down => app.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_selection(-1),
        KeyCode::Char('a') => app.open_add(),
        KeyCode::Char('e') => app.open_edit(),
        KeyCode::Char('d') => app.request_delete(),
        KeyCode::Char('c') => app.copy_password(),
        KeyCode::Char('r') | KeyCode::Char(' ') => {
            app.show_password = !app.show_password;
        }
        _ => {}
    }
}

fn handle_form(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.screen = Screen::Main;
            app.status = "Cancelled".into();
        }
        KeyCode::Enter => app.save_form(),
        KeyCode::Tab | KeyCode::Down => {
            app.form.field = app.form.field.next();
        }
        KeyCode::BackTab | KeyCode::Up => {
            app.form.field = app.form.field.prev();
        }
        KeyCode::Backspace => {
            app.active_form_value_mut().pop();
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.active_form_value_mut().push(c);
        }
        _ => {}
    }
}

fn handle_confirm(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_delete(true),
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => app.confirm_delete(false),
        _ => {}
    }
}
