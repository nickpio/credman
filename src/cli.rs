use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, Password};
use rand::Rng;
use uuid::Uuid;

use crate::crypto::{generate_mnemonic, normalize_mnemonic, validate_mnemonic};
use crate::model::Entry;
use crate::tui;
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
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let vault_path = cli.vault.unwrap_or_else(VaultFile::default_path);

    match cli.command {
        None | Some(Commands::Tui) => tui::run(&vault_path),
        Some(Commands::Init { force }) => cmd_init(&vault_path, force),
        Some(Commands::Add { generate, length }) => cmd_add(&vault_path, generate, length),
        Some(Commands::Get {
            query,
            password_only,
            clipboard,
        }) => cmd_get(&vault_path, &query, password_only, clipboard),
        Some(Commands::List { secrets }) => cmd_list(&vault_path, secrets),
        Some(Commands::Edit { query }) => cmd_edit(&vault_path, &query),
        Some(Commands::Rm { query, yes }) => cmd_rm(&vault_path, &query, yes),
    }
}

fn prompt_seed() -> Result<String> {
    let phrase: String = Input::new()
        .with_prompt("Seed phrase")
        .allow_empty(false)
        .interact_text()
        .context("failed to read seed phrase")?;
    let normalized = normalize_mnemonic(&phrase);
    validate_mnemonic(&normalized).context("invalid seed phrase")?;
    Ok(normalized)
}

fn unlock(path: &PathBuf) -> Result<UnlockedVault> {
    let phrase = prompt_seed()?;
    UnlockedVault::unlock(path, &phrase).context("failed to unlock vault")
}

fn cmd_init(path: &PathBuf, force: bool) -> Result<()> {
    if path.exists() {
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
        std::fs::remove_file(path)?;
    }

    let phrase = generate_mnemonic()?;

    println!("Write down this 12-word seed phrase and store it offline.");
    println!("It is the ONLY way to unlock your vault. It will not be shown again.\n");
    println!("{phrase}\n");

    Confirm::new()
        .with_prompt("I have written down my seed phrase")
        .default(true)
        .interact()?;

    // Clear the terminal so the phrase is no longer visible before confirmation.
    print!("\x1B[2J\x1B[1;1H");
    let _ = io::stdout().flush();

    println!("Re-enter your seed phrase to confirm you wrote it down correctly.\n");
    let confirmed: String = Input::new()
        .with_prompt("Seed phrase")
        .allow_empty(false)
        .interact_text()?;
    if normalize_mnemonic(&confirmed) != normalize_mnemonic(&phrase) {
        bail!("confirmation did not match; vault not created");
    }

    UnlockedVault::create(path, &phrase)?;
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

fn cmd_add(path: &PathBuf, generate: bool, length: usize) -> Result<()> {
    let mut vault = unlock(path)?;
    let name: String = Input::new().with_prompt("Name").interact_text()?;
    let username: String = Input::new()
        .with_prompt("Username")
        .allow_empty(true)
        .interact_text()?;
    let password = if generate {
        let p = generate_password(length);
        println!("Generated password ({length} chars)");
        p
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
    println!("Added '{}' ({})", entry.name, entry.id);
    vault.data.entries.push(entry);
    vault.persist()?;
    Ok(())
}

fn cmd_get(path: &PathBuf, query: &str, password_only: bool, clipboard: bool) -> Result<()> {
    let vault = unlock(path)?;
    let entry = vault
        .data
        .find(query)
        .with_context(|| format!("no entry matching '{query}'"))?;

    if clipboard {
        let mut clip = arboard::Clipboard::new().context("clipboard unavailable")?;
        clip.set_text(entry.password.clone())
            .context("failed to set clipboard")?;
        eprintln!("Password copied to clipboard.");
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
    let entry = vault
        .data
        .find_mut(query)
        .with_context(|| format!("no entry matching '{query}'"))?;

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
    println!("Updated '{}'", entry.name);
    vault.persist()?;
    Ok(())
}

fn cmd_rm(path: &PathBuf, query: &str, yes: bool) -> Result<()> {
    let mut vault = unlock(path)?;
    let name = vault
        .data
        .find(query)
        .with_context(|| format!("no entry matching '{query}'"))?
        .name
        .clone();
    if !yes
        && !Confirm::new()
            .with_prompt(format!("Delete '{name}'?"))
            .default(false)
            .interact()?
    {
        bail!("aborted");
    }
    vault.data.remove(query);
    vault.persist()?;
    println!("Deleted '{name}'");
    let _ = io::stdout().flush();
    Ok(())
}
