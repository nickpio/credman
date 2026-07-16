use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, InputField, Screen, StatusKind};

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    match app.screen {
        Screen::Unlock => draw_unlock(f, app, area),
        Screen::Main | Screen::ConfirmDelete => draw_main(f, app, area),
        Screen::Add | Screen::Edit => {
            draw_main(f, app, area);
            draw_form_modal(f, app, area);
        }
        Screen::Quit => {}
    }
}

fn status_style(kind: StatusKind) -> Style {
    match kind {
        StatusKind::Info => Style::default().fg(Color::DarkGray),
        StatusKind::Success => Style::default().fg(Color::Green),
        StatusKind::Error => Style::default().fg(Color::Red),
    }
}

fn draw_unlock(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Length(8),
            Constraint::Min(1),
        ])
        .split(area);

    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "credman",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("Unlock vault with your 12-word BIP39 seed phrase"),
    ])
    .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    let lines = if app.unlocking {
        vec![
            Line::from(Span::styled(
                "Unlocking…",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Deriving key — please wait"),
        ]
    } else {
        let visibility = if app.show_seed { "shown" } else { "hidden" };
        let mut lines = vec![
            Line::from(format!("Phrase: {}", app.seed_display())),
            Line::from(format!(
                "Words: {}/12 · Ctrl+R toggle ({visibility})",
                app.seed_word_count()
            )),
            Line::from(""),
            Line::from("Enter to unlock · Ctrl+C / Esc to quit"),
        ];
        if let Some(err) = &app.unlock_error {
            lines.push(Line::from(Span::styled(
                err.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        lines
    };

    let box_w = chunks[1].width.min(80);
    let box_x = chunks[1].x + (chunks[1].width.saturating_sub(box_w)) / 2;
    let unlock_area = Rect::new(box_x, chunks[1].y, box_w, chunks[1].height);
    let block = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Unlock "))
        .alignment(ratatui::layout::Alignment::Left);
    f.render_widget(block, unlock_area);

    let status = Paragraph::new(app.status.as_str()).style(status_style(app.status_kind));
    f.render_widget(status, chunks[2]);
}

fn draw_main(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[0]);

    let items: Vec<ListItem> = app
        .filtered_indices
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let e = &app.vault.as_ref().unwrap().data.entries[idx];
            let label = if e.username.is_empty() {
                e.name.clone()
            } else {
                format!("{}  <{}>", e.name, e.username)
            };
            let style = if i == app.selected {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(label).style(style)
        })
        .collect();

    let title = if app.filtering {
        format!(" Entries [/{}] ", app.filter)
    } else if app.filter.is_empty() {
        " Entries ".into()
    } else {
        format!(" Entries (filter: {}) ", app.filter)
    };
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(list, body[0]);

    let detail = match app.selected_entry_index() {
        Some(idx) => {
            let e = &app.vault.as_ref().unwrap().data.entries[idx];
            let pw = if app.show_password {
                e.password.clone()
            } else if e.password.is_empty() {
                String::new()
            } else {
                "••••••••".into()
            };
            vec![
                Line::from(vec![
                    Span::styled("Name:     ", Style::default().fg(Color::Cyan)),
                    Span::raw(e.name.clone()),
                ]),
                Line::from(vec![
                    Span::styled("Username: ", Style::default().fg(Color::Cyan)),
                    Span::raw(e.username.clone()),
                ]),
                Line::from(vec![
                    Span::styled("Password: ", Style::default().fg(Color::Cyan)),
                    Span::raw(pw),
                ]),
                Line::from(vec![
                    Span::styled("URL:      ", Style::default().fg(Color::Cyan)),
                    Span::raw(e.url.clone()),
                ]),
                Line::from(vec![
                    Span::styled("Tags:     ", Style::default().fg(Color::Cyan)),
                    Span::raw(e.tags.join(", ")),
                ]),
                Line::from(vec![
                    Span::styled("Notes:    ", Style::default().fg(Color::Cyan)),
                    Span::raw(e.notes.clone()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Id:       ", Style::default().fg(Color::DarkGray)),
                    Span::styled(e.id.to_string(), Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(vec![
                    Span::styled("Updated:  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        e.updated_at.to_rfc3339(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ]
        }
        None => vec![Line::from(
            app.list_empty_message()
                .unwrap_or_else(|| "No entry selected".into()),
        )],
    };
    let detail_widget = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });
    f.render_widget(detail_widget, body[1]);

    let status = Paragraph::new(app.status_line()).style(status_style(app.status_kind));
    f.render_widget(status, chunks[1]);

    if app.screen == Screen::ConfirmDelete {
        draw_confirm(f, app, area);
    }
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(40, 5, area);
    f.render_widget(Clear, popup);
    let name = app.delete_target_name().unwrap_or("selected entry");
    let p = Paragraph::new(format!("Delete '{name}'?\n\n[y] yes   [n] no"))
        .block(Block::default().borders(Borders::ALL).title(" Confirm "))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(p, popup);
}

fn draw_form_modal(f: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(70, 16, area);
    f.render_widget(Clear, popup);
    let title = if app.screen == Screen::Add {
        " Add entry "
    } else {
        " Edit entry "
    };
    let field_style = |field: InputField| {
        if app.form.field == field {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        }
    };
    let pw_display = app.form_password_display();
    let lines = vec![
        Line::from(Span::styled(
            format!("Name:     {}", app.form.name),
            field_style(InputField::Name),
        )),
        Line::from(Span::styled(
            format!("Username: {}", app.form.username),
            field_style(InputField::Username),
        )),
        Line::from(Span::styled(
            format!("Password: {pw_display}"),
            field_style(InputField::Password),
        )),
        Line::from(Span::styled(
            format!("URL:      {}", app.form.url),
            field_style(InputField::Url),
        )),
        Line::from(Span::styled(
            format!("Notes:    {}", app.form.notes),
            field_style(InputField::Notes),
        )),
        Line::from(Span::styled(
            format!("Tags:     {}", app.form.tags),
            field_style(InputField::Tags),
        )),
        Line::from(""),
        Line::from("Tab/↑↓ fields · Enter save · Esc cancel"),
    ];
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, popup);
}

fn centered_rect(percent_x: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height.min(100)) / 2),
            Constraint::Length(height),
            Constraint::Percentage((100 - height.min(100)) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
