use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::{App, Screen};

/// Returns true when the app should quit.
pub fn handle_event(app: &mut App) -> Result<bool> {
    app.tick_clipboard();
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
        Screen::Setup => handle_setup(app, key.code),
        Screen::Unlock => handle_unlock(app, key),
        Screen::Main => handle_main(app, key),
        Screen::Add | Screen::Edit => handle_form(app, key.code),
        Screen::ConfirmDelete => handle_confirm(app, key.code),
        Screen::Quit => return Ok(true),
    }
    Ok(app.screen == Screen::Quit)
}

fn handle_setup(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.screen = Screen::Quit;
        }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            app.info("Exit the TUI, then run: credman init");
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            app.info("Exit the TUI, then run: credman restore");
        }
        _ => {}
    }
}

fn handle_unlock(app: &mut App, key: KeyEvent) {
    if app.unlocking {
        return;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
        app.show_seed = !app.show_seed;
        return;
    }

    match key.code {
        KeyCode::Esc => app.screen = Screen::Quit,
        KeyCode::Enter => app.start_unlock(),
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

fn handle_main(app: &mut App, key: KeyEvent) {
    if app.palette_open {
        handle_palette(app, key.code);
        return;
    }
    if app.show_help {
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                app.show_help = false;
                app.info("Help closed");
            }
            _ => {}
        }
        return;
    }
    if app.filtering {
        match key.code {
            KeyCode::Esc => {
                app.filtering = false;
                app.filter.clear();
                app.recompute_filter();
                app.info("Filter cleared");
            }
            KeyCode::Enter => {
                app.filtering = false;
                app.info(format!("Filter: {}", app.filter));
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

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.screen = Screen::Quit,
        KeyCode::Char('?') => {
            app.show_help = true;
            app.info("Press ? or Esc to close help");
        }
        KeyCode::Char(':') => app.open_palette(),
        KeyCode::Char('/') => {
            app.filtering = true;
            app.info("Type to filter, Enter done, Esc clear");
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

fn handle_palette(app: &mut App, code: KeyCode) {
    let actions = app.filtered_palette_actions();
    match code {
        KeyCode::Esc => {
            app.close_palette();
            app.info("Cancelled");
        }
        KeyCode::Enter => {
            if let Some((_, _, _, action)) = actions.get(app.palette_selected) {
                app.run_palette_action(*action);
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            if !actions.is_empty() {
                app.palette_selected = (app.palette_selected + 1) % actions.len();
            }
        }
        KeyCode::Up | KeyCode::BackTab => {
            if !actions.is_empty() {
                app.palette_selected = (app.palette_selected + actions.len() - 1) % actions.len();
            }
        }
        KeyCode::Backspace => {
            app.palette_query.pop();
            app.palette_selected = 0;
        }
        KeyCode::Char(c) if !c.is_control() => {
            app.palette_query.push(c);
            app.palette_selected = 0;
        }
        _ => {}
    }
}

fn handle_form(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.screen = Screen::Main;
            app.info("Cancelled");
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
            app.push_form_char(c);
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
