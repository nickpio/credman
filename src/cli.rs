use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dialoguer::{Confirm, Input, Password};
use rand::Rng;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::clipboard::{self, HelperSchedule};
use crate::crypto::{generate_mnemonic, normalize_mnemonic, validate_mnemonic};
use crate::model::Entry;
use crate::tui;
use crate::validation::{validate_entry, validate_generated_password_length};
use crate::vault::{UnlockedVault, VaultFile};

#[derive(Parser, Debug)]
#[command(name = "credman", about = "Local credential manager unlocked with a BIP39 seed phrase")]
pub struct Cli {
    /// Path to vault file (default: ~/.credman/vault or $CREDMAN_VAULT)
    #[arg(long, global = true, env = "CREDMAN_VAULT")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new vault and display the 12-word seed phrase
    Init {
        /// Overwrite existing vault (dangerous)
        #[arg(long)]
        force: bool,
    },
    /// Unlock an existing vault file, or create one from an existing seed
    Restore {
        /// Overwrite existing vault with a new empty vault (dangerous)
        #[arg(long)]
        force: bool,
    },
    /// Add a credential
    Add {
        /// Generate a random password
        #[arg(long)]
        generate: bool,
        /// Length for --generate (default 24)
        #[arg(long, default_value_t = 24)]
        length: usize,
    },
    /// Get a credential by name or id
    Get {
        query: String,
        #[arg(long)]
        password_only: bool,
        #[arg(long)]
        clipboard: bool,
    },
    /// List credentials
    List {
        #[arg(long)]
        secrets: bool,
    },
    /// Edit a credential
    Edit { query: String },
    /// Remove a credential
    Rm {
        query: String,
        #[arg(long)]
        yes: bool,
    },
    /// Open the interactive TUI
    Tui,
    #[command(hide = true)]
    ClipboardClear,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(VaultFile::default_path);

    match cli.command {
        None | Some(Commands::Tui) => tui::run(&vault_path),
        Some(Commands::Init { force }) => cmd_init(&vault_path, force),
        Some(Commands::Restore { force }) => cmd_restore(&vault_path, force),
        Some(Commands::Add { generate, length }) => cmd_add(&vault_path, generate, length),
        Some(Commands::Get {
            query,
            password_only,
            clipboard,
        }) => cmd_get(&vault_path, &query, password_only, clipboard),
        Some(Commands::List { secrets }) => cmd_list(&vault_path, secrets),
        Some(Commands::Edit { query }) => cmd_edit(&vault_path, &query),
        Some(Commands::Rm { query, yes }) => cmd_rm(&vault_path, &query, yes),
        Some(Commands::ClipboardClear) => {
            clipboard::run_clear_helper().context("clipboard clear helper failed")
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable masked seed input")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

fn masked_seed(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(|_| "••••")
        .collect::<Vec<_>>()
        .join(" ")
}

fn draw_seed_prompt(out: &mut impl Write, phrase: &str, revealed: bool) -> io::Result<()> {
    let display = if revealed {
        phrase.to_string()
    } else {
        masked_seed(phrase)
    };
    let visibility = if revealed { "shown" } else { "hidden" };
    write!(
        out,
        "\r\x1B[2KSeed phrase [{visibility}; Ctrl+R toggle]: {display} ({}/12 words)",
        phrase.split_whitespace().count()
    )?;
    out.flush()
}

fn read_seed_interactive() -> Result<String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Password::new()
            .with_prompt("Seed phrase (hidden)")
            .interact()
            .context("failed to read seed phrase");
    }

    let raw_mode = RawModeGuard::new()?;
    let mut out = io::stderr();
    let mut phrase = String::new();
    let mut revealed = false;
    draw_seed_prompt(&mut out, &phrase, revealed)?;

    let result = loop {
        match event::read().context("failed to read seed phrase")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('c') => break Err(anyhow::anyhow!("aborted")),
                        KeyCode::Char('r') => revealed = !revealed,
                        KeyCode::Char('u') => phrase.clear(),
                        KeyCode::Char('w') => {
                            while phrase.chars().last().is_some_and(|c| c.is_whitespace()) {
                                phrase.pop();
                            }
                            while phrase.chars().last().is_some_and(|c| !c.is_whitespace()) {
                                phrase.pop();
                            }
                        }
                        _ => continue,
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => break Err(anyhow::anyhow!("aborted")),
                        KeyCode::Enter if !phrase.trim().is_empty() => break Ok(phrase),
                        KeyCode::Backspace => {
                            phrase.pop();
                        }
                        KeyCode::Char(c) if !c.is_control() => phrase.push(c),
                        _ => continue,
                    }
                }
                draw_seed_prompt(&mut out, &phrase, revealed)?;
            }
            Event::Paste(text) => {
                phrase.push_str(&text.replace(['\r', '\n'], " "));
                draw_seed_prompt(&mut out, &phrase, revealed)?;
            }
            _ => {}
        }
    };

    drop(raw_mode);
    write!(out, "\r\x1B[2K")?;
    writeln!(out)?;
    result
}

fn prompt_seed() -> Result<Zeroizing<String>> {
    let mut phrase = read_seed_interactive()?;
    let normalized = normalize_mnemonic(&phrase);
    phrase.zeroize();
    validate_mnemonic(&normalized).context("invalid seed phrase")?;
    Ok(Zeroizing::new(normalized))
}

fn unlock(path: &PathBuf) -> Result<UnlockedVault> {
    let phrase = prompt_seed()?;
    UnlockedVault::unlock(path, &phrase).context("failed to unlock vault")
}

fn cmd_init(path: &PathBuf, force: bool) -> Result<()> {
    let replace = path.exists();
    if replace {
        if !force {
            bail!(
                "vault already exists at {}. Use --force to overwrite.",
                path.display()
            );
        }
        if !Confirm::new()
            .with_prompt(format!(
                "Overwrite vault at {}? This cannot be undone.",
                path.display()
            ))
            .default(false)
            .interact()?
        {
            bail!("aborted");
        }
    }

    let phrase = Zeroizing::new(generate_mnemonic()?);

    println!("Write down this 12-word seed phrase and store it offline.");
    println!("It is the ONLY way to unlock your vault. It will not be shown again.\n");
    println!("{}\n", phrase.as_str());

    Confirm::new()
        .with_prompt("I have written down my seed phrase")
        .default(true)
        .interact()?;

    // Clear the terminal so the phrase is no longer visible before confirmation.
    print!("\x1B[2J\x1B[1;1H");
    let _ = io::stdout().flush();

    println!("Re-enter your seed phrase to confirm you wrote it down correctly.\n");
    let confirmed = prompt_seed()?;
    if confirmed.as_str() != phrase.as_str() {
        bail!("confirmation did not match; vault not created");
    }

    if replace {
        UnlockedVault::replace(path, &phrase)?;
    } else {
        UnlockedVault::create(path, &phrase)?;
    }
    println!("Vault created at {}", path.display());
    Ok(())
}

fn cmd_restore(path: &PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        println!(
            "Found vault at {}. Enter your seed phrase to verify access.\n",
            path.display()
        );
        let phrase = prompt_seed()?;
        let vault = UnlockedVault::unlock(path, &phrase).context("failed to unlock vault")?;
        println!(
            "Vault verified at {} ({} entries).",
            path.display(),
            vault.data.entries.len()
        );
        println!("You can use credman normally on this device.");
        return Ok(());
    }

    if path.exists() {
        if !Confirm::new()
            .with_prompt(format!(
                "Overwrite vault at {} with a new empty vault? This cannot be undone.",
                path.display()
            ))
            .default(false)
            .interact()?
        {
            bail!("aborted");
        }
    } else {
        println!(
            "No vault at {}.\n\
             If you have an encrypted vault backup, copy it there and run `credman restore` again.\n\
             Otherwise, enter an existing seed phrase to create a new empty vault.\n",
            path.display()
        );
    }

    let phrase = prompt_seed()?;
    println!("\nRe-enter your seed phrase to confirm.\n");
    let confirmed = prompt_seed()?;
    if confirmed.as_str() != phrase.as_str() {
        bail!("confirmation did not match; vault not created");
    }

    if path.exists() {
        UnlockedVault::replace(path, &phrase)?;
    } else {
        UnlockedVault::create(path, &phrase)?;
    }
    println!("Vault created at {}", path.display());
    Ok(())
}

fn generate_password(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn offer_generated_password(password: &str, entry_id: Uuid) -> Result<()> {
    let copy = Confirm::new()
        .with_prompt("Copy generated password to clipboard?")
        .default(true)
        .interact()?;
    if copy {
        match clipboard::copy_with_helper(password) {
            Ok(HelperSchedule::Scheduled) => {
                eprintln!(
                    "Generated password copied to clipboard (clears in {} seconds if unchanged).",
                    clipboard::CLIPBOARD_TTL.as_secs()
                );
                return Ok(());
            }
            Ok(HelperSchedule::Unavailable(error)) => {
                eprintln!(
                    "Generated password copied, but automatic clearing could not be scheduled: {error}. Clear the clipboard manually."
                );
                return Ok(());
            }
            Err(error) => eprintln!("Clipboard unavailable: {error}"),
        }
    }

    let reveal = Confirm::new()
        .with_prompt("Show generated password in the terminal?")
        .default(false)
        .interact()?;
    if reveal {
        println!("Generated password: {password}");
    } else {
        println!(
            "Generated password stored. Retrieve it with `credman get {entry_id} --password-only`."
        );
    }
    Ok(())
}

fn cmd_add(path: &PathBuf, generate: bool, length: usize) -> Result<()> {
    if generate {
        validate_generated_password_length(length)?;
    }
    let mut vault = unlock(path)?;
    let name: String = Input::new().with_prompt("Name").interact_text()?;
    let username: String = Input::new()
        .with_prompt("Username")
        .allow_empty(true)
        .interact_text()?;
    let generated_password = if generate {
        Some(Zeroizing::new(generate_password(length)))
    } else {
        None
    };
    let password = if let Some(generated) = &generated_password {
        generated.as_str().to_string()
    } else {
        Password::new()
            .with_prompt("Password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    };
    let url: String = Input::new()
        .with_prompt("URL")
        .allow_empty(true)
        .interact_text()?;
    let notes: String = Input::new()
        .with_prompt("Notes")
        .allow_empty(true)
        .interact_text()?;
    let tags_raw: String = Input::new()
        .with_prompt("Tags (comma-separated)")
        .allow_empty(true)
        .interact_text()?;
    let tags: Vec<String> = tags_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let entry = Entry {
        id: Uuid::new_v4(),
        name,
        username,
        password,
        url,
        notes,
        tags,
        updated_at: Utc::now(),
    };
    validate_entry(&entry)?;
    let entry_id = entry.id;
    let entry_name = entry.name.clone();
    vault.data.entries.push(entry);
    vault.persist()?;
    println!("Added '{entry_name}' ({entry_id})");
    if let Some(password) = generated_password {
        if let Err(error) = offer_generated_password(&password, entry_id) {
            eprintln!(
                "Could not present the generated password: {error}. Retrieve it with `credman get {entry_id} --password-only`."
            );
        }
    }
    Ok(())
}

fn cmd_get(path: &PathBuf, query: &str, password_only: bool, clipboard: bool) -> Result<()> {
    let vault = unlock(path)?;
    let entry = vault.data.find(query)?;

    if clipboard {
        match crate::clipboard::copy_with_helper(&entry.password)? {
            HelperSchedule::Scheduled => eprintln!(
                "Password copied to clipboard (clears in {} seconds if unchanged).",
                crate::clipboard::CLIPBOARD_TTL.as_secs()
            ),
            HelperSchedule::Unavailable(error) => eprintln!(
                "Password copied, but automatic clearing could not be scheduled: {error}. Clear the clipboard manually."
            ),
        }
        return Ok(());
    }

    if password_only {
        println!("{}", entry.password);
        return Ok(());
    }

    println!("id:         {}", entry.id);
    println!("name:       {}", entry.name);
    println!("username:   {}", entry.username);
    println!("password:   {}", entry.password);
    println!("url:        {}", entry.url);
    println!("notes:      {}", entry.notes);
    println!("tags:       {}", entry.tags.join(", "));
    println!("updated_at: {}", entry.updated_at.to_rfc3339());
    Ok(())
}

fn cmd_list(path: &PathBuf, secrets: bool) -> Result<()> {
    let vault = unlock(path)?;
    if vault.data.entries.is_empty() {
        println!("(empty vault)");
        return Ok(());
    }
    for e in &vault.data.entries {
        if secrets {
            println!(
                "{}\t{}\t{}\t{}\t[{}]",
                e.id,
                e.name,
                e.username,
                e.password,
                e.tags.join(",")
            );
        } else {
            println!(
                "{}\t{}\t{}\t[{}]",
                e.id,
                e.name,
                e.username,
                e.tags.join(",")
            );
        }
    }
    Ok(())
}

fn cmd_edit(path: &PathBuf, query: &str) -> Result<()> {
    let mut vault = unlock(path)?;
    let entry = vault.data.find_mut(query)?;

    let name: String = Input::new()
        .with_prompt("Name")
        .with_initial_text(&entry.name)
        .interact_text()?;
    let username: String = Input::new()
        .with_prompt("Username")
        .with_initial_text(&entry.username)
        .allow_empty(true)
        .interact_text()?;
    let change_pw = Confirm::new()
        .with_prompt("Change password?")
        .default(false)
        .interact()?;
    if change_pw {
        entry.password = Password::new()
            .with_prompt("Password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?;
    }
    let url: String = Input::new()
        .with_prompt("URL")
        .with_initial_text(&entry.url)
        .allow_empty(true)
        .interact_text()?;
    let notes: String = Input::new()
        .with_prompt("Notes")
        .with_initial_text(&entry.notes)
        .allow_empty(true)
        .interact_text()?;
    let tags_raw: String = Input::new()
        .with_prompt("Tags (comma-separated)")
        .with_initial_text(&entry.tags.join(", "))
        .allow_empty(true)
        .interact_text()?;
    entry.name = name;
    entry.username = username;
    entry.url = url;
    entry.notes = notes;
    entry.tags = tags_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    entry.updated_at = Utc::now();
    validate_entry(entry)?;
    println!("Updated '{}'", entry.name);
    vault.persist()?;
    Ok(())
}

fn cmd_rm(path: &PathBuf, query: &str, yes: bool) -> Result<()> {
    let mut vault = unlock(path)?;
    let entry = vault.data.find(query)?;
    let id = entry.id;
    let name = entry.name.clone();
    if !yes
        && !Confirm::new()
            .with_prompt(format!("Delete '{name}'?"))
            .default(false)
            .interact()?
    {
        bail!("aborted");
    }
    vault.data.remove(&id.to_string())?;
    vault.persist()?;
    println!("Deleted '{name}'");
    let _ = io::stdout().flush();
    Ok(())
}
