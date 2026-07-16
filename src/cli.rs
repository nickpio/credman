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

use crate::backup::{
    self, merge_entries, BackupSecretKind, EncryptedBackup, MIN_PASSPHRASE_CHARS,
};
use crate::clipboard::{self, HelperSchedule};
use crate::crypto::{generate_mnemonic, normalize_mnemonic, seed_fingerprint, validate_mnemonic};
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

    /// Seed phrase for non-interactive use (INSECURE: may appear in shell history / process lists)
    #[arg(long, global = true)]
    pub seed: Option<String>,

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
    /// Show vault path and whether it exists (no unlock)
    Status,
    /// Copy the encrypted vault to a timestamped file in DIR (no unlock)
    Backup {
        /// Directory to write the backup into (created if missing)
        dir: PathBuf,
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
    /// Export an encrypted JSON backup of the vault
    Export {
        /// Destination path for the backup JSON file
        path: PathBuf,
        /// Encrypt the backup with a separate passphrase instead of the seed
        #[arg(long)]
        passphrase: bool,
    },
    /// Import an encrypted JSON backup into the vault
    Import {
        /// Path to the backup JSON file
        path: PathBuf,
        /// Merge entries by id instead of replacing the vault contents
        #[arg(long)]
        merge: bool,
        /// Skip confirmation prompts
        #[arg(long)]
        yes: bool,
    },
    #[command(hide = true)]
    ClipboardClear,
}

pub fn run() -> Result<()> {
    let mut cli = Cli::parse();
    let vault_path = cli.vault.take().unwrap_or_else(VaultFile::default_path);
    let mut seed = cli.seed.take().map(Zeroizing::new);
    let seed_ref = seed.as_ref().map(|s| s.as_str());

    let result = match cli.command {
        None | Some(Commands::Tui) => tui::run(&vault_path),
        Some(Commands::Init { force }) => cmd_init(&vault_path, force, seed_ref),
        Some(Commands::Status) => cmd_status(&vault_path),
        Some(Commands::Backup { dir }) => cmd_backup(&vault_path, &dir),
        Some(Commands::Restore { force }) => cmd_restore(&vault_path, force, seed_ref),
        Some(Commands::Add { generate, length }) => {
            cmd_add(&vault_path, generate, length, seed_ref)
        }
        Some(Commands::Get {
            query,
            password_only,
            clipboard,
        }) => cmd_get(&vault_path, &query, password_only, clipboard, seed_ref),
        Some(Commands::List { secrets }) => cmd_list(&vault_path, secrets, seed_ref),
        Some(Commands::Edit { query }) => cmd_edit(&vault_path, &query, seed_ref),
        Some(Commands::Rm { query, yes }) => cmd_rm(&vault_path, &query, yes, seed_ref),
        Some(Commands::Export { path, passphrase }) => {
            cmd_export(&vault_path, &path, passphrase, seed_ref)
        }
        Some(Commands::Import { path, merge, yes }) => {
            cmd_import(&vault_path, &path, merge, yes, seed_ref)
        }
        Some(Commands::ClipboardClear) => {
            clipboard::run_clear_helper().context("clipboard clear helper failed")
        }
    };

    if let Some(ref mut s) = seed {
        s.zeroize();
    }
    result
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

fn prompt_seed(cli_seed: Option<&str>) -> Result<Zeroizing<String>> {
    if let Some(seed) = cli_seed {
        eprintln!(
            "warning: --seed exposes the phrase in shell history and process lists; \
             prefer interactive entry for anything beyond disposable automation."
        );
        let normalized = Zeroizing::new(normalize_mnemonic(seed));
        validate_mnemonic(&normalized).context("invalid seed phrase")?;
        return Ok(normalized);
    }
    let mut phrase = read_seed_interactive()?;
    let normalized = normalize_mnemonic(&phrase);
    phrase.zeroize();
    validate_mnemonic(&normalized).context("invalid seed phrase")?;
    Ok(Zeroizing::new(normalized))
}

fn unlock(path: &PathBuf, cli_seed: Option<&str>) -> Result<UnlockedVault> {
    let phrase = prompt_seed(cli_seed)?;
    UnlockedVault::unlock(path, &phrase).context("failed to unlock vault")
}

fn offer_seed_fingerprint(phrase: &str) -> Result<()> {
    let show = if io::stdin().is_terminal() {
        Confirm::new()
            .with_prompt(
                "Show a seed fingerprint to write down for later verification? (not a secret)",
            )
            .default(true)
            .interact()?
    } else {
        // Non-interactive: always print so automation can capture it.
        true
    };
    if !show {
        return Ok(());
    }
    let fp = seed_fingerprint(phrase).context("failed to compute seed fingerprint")?;
    println!("\nSeed fingerprint: {fp}");
    println!("Write this next to your offline backup. It is not stored by credman.");
    println!("Later you can recompute it after unlocking to confirm you have the same seed.");
    Ok(())
}

fn device_hostname() -> String {
    gethostname::gethostname()
        .to_string_lossy()
        .into_owned()
}

fn cmd_init(path: &PathBuf, force: bool, cli_seed: Option<&str>) -> Result<()> {
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
    let confirmed = prompt_seed(cli_seed)?;
    if confirmed.as_str() != phrase.as_str() {
        bail!("confirmation did not match; vault not created");
    }

    if replace {
        UnlockedVault::replace(path, &phrase)?;
    } else {
        UnlockedVault::create(path, &phrase)?;
    }
    println!("Vault created at {}", path.display());
    offer_seed_fingerprint(&phrase)?;
    Ok(())
}

fn cmd_restore(path: &PathBuf, force: bool, cli_seed: Option<&str>) -> Result<()> {
    if path.exists() && !force {
        println!(
            "Found vault at {}. Enter your seed phrase to verify access.\n",
            path.display()
        );
        let phrase = prompt_seed(cli_seed)?;
        let vault = UnlockedVault::unlock(path, &phrase).context("failed to unlock vault")?;
        let host = device_hostname();
        println!(
            "Vault restored — {} entries loaded on {host}.",
            vault.data.entries.len()
        );
        println!("Vault path: {}", path.display());
        println!("You can use credman normally on this device.");
        offer_seed_fingerprint(&phrase)?;
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

    let phrase = prompt_seed(cli_seed)?;
    if cli_seed.is_none() {
        println!("\nRe-enter your seed phrase to confirm.\n");
        let confirmed = prompt_seed(None)?;
        if confirmed.as_str() != phrase.as_str() {
            bail!("confirmation did not match; vault not created");
        }
    }

    if path.exists() {
        UnlockedVault::replace(path, &phrase)?;
    } else {
        UnlockedVault::create(path, &phrase)?;
    }
    let host = device_hostname();
    println!("Vault restored — 0 entries loaded on {host}.");
    println!("Vault created at {}", path.display());
    offer_seed_fingerprint(&phrase)?;
    Ok(())
}

fn cmd_status(path: &PathBuf) -> Result<()> {
    println!("vault:  {}", path.display());
    if path.exists() {
        let meta = std::fs::metadata(path).with_context(|| {
            format!("failed to read vault metadata at {}", path.display())
        })?;
        println!("status: present");
        println!("size:   {} bytes", meta.len());
        if let Ok(modified) = meta.modified() {
            let dt: chrono::DateTime<Utc> = modified.into();
            println!("mtime:  {}", dt.to_rfc3339());
        }
    } else {
        println!("status: missing");
        println!("hint:   run `credman init` (new) or `credman restore` (existing seed)");
    }
    Ok(())
}

fn cmd_backup(vault_path: &PathBuf, dir: &PathBuf) -> Result<()> {
    let dest = VaultFile::backup(vault_path, dir).with_context(|| {
        format!(
            "failed to back up vault at {} to {}",
            vault_path.display(),
            dir.display()
        )
    })?;
    println!("Backup written to {}", dest.display());
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

fn cmd_add(path: &PathBuf, generate: bool, length: usize, cli_seed: Option<&str>) -> Result<()> {
    if generate {
        validate_generated_password_length(length)?;
    }
    let mut vault = unlock(path, cli_seed)?;
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

fn cmd_get(
    path: &PathBuf,
    query: &str,
    password_only: bool,
    clipboard: bool,
    cli_seed: Option<&str>,
) -> Result<()> {
    let vault = unlock(path, cli_seed)?;
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

fn cmd_list(path: &PathBuf, secrets: bool, cli_seed: Option<&str>) -> Result<()> {
    let vault = unlock(path, cli_seed)?;
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

fn cmd_edit(path: &PathBuf, query: &str, cli_seed: Option<&str>) -> Result<()> {
    let mut vault = unlock(path, cli_seed)?;
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

fn cmd_rm(path: &PathBuf, query: &str, yes: bool, cli_seed: Option<&str>) -> Result<()> {
    let mut vault = unlock(path, cli_seed)?;
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

fn prompt_passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    let prompt_text = format!("Backup passphrase (min {MIN_PASSPHRASE_CHARS} characters)");
    let phrase = if confirm {
        Password::new()
            .with_prompt(&prompt_text)
            .with_confirmation("Confirm passphrase", "Passphrases do not match")
            .interact()
            .context("failed to read passphrase")?
    } else {
        Password::new()
            .with_prompt(&prompt_text)
            .interact()
            .context("failed to read passphrase")?
    };
    backup::validate_passphrase(&phrase)?;
    Ok(Zeroizing::new(phrase))
}

fn cmd_export(
    vault_path: &PathBuf,
    out_path: &PathBuf,
    use_passphrase: bool,
    cli_seed: Option<&str>,
) -> Result<()> {
    if out_path.exists() {
        if !Confirm::new()
            .with_prompt(format!("Overwrite {}?", out_path.display()))
            .default(false)
            .interact()?
        {
            bail!("aborted");
        }
    }

    let phrase = prompt_seed(cli_seed)?;
    let vault = UnlockedVault::unlock(vault_path, &phrase).context("failed to unlock vault")?;

    let backup = if use_passphrase {
        let passphrase = prompt_passphrase(true)?;
        EncryptedBackup::encrypt_with_passphrase(&vault.data, &passphrase)?
    } else {
        EncryptedBackup::encrypt_with_seed(&vault.data, &phrase)?
    };

    backup
        .save(out_path)
        .with_context(|| format!("failed to write backup to {}", out_path.display()))?;
    println!(
        "Exported {} entr{} to {} ({})",
        vault.data.entries.len(),
        if vault.data.entries.len() == 1 {
            "y"
        } else {
            "ies"
        },
        out_path.display(),
        if use_passphrase {
            "passphrase-encrypted"
        } else {
            "seed-encrypted"
        }
    );
    Ok(())
}

fn cmd_import(
    vault_path: &PathBuf,
    in_path: &PathBuf,
    merge: bool,
    yes: bool,
    cli_seed: Option<&str>,
) -> Result<()> {
    let backup = EncryptedBackup::load(in_path)
        .with_context(|| format!("failed to read backup from {}", in_path.display()))?;

    let (imported, seed) = match backup.secret {
        BackupSecretKind::Passphrase => {
            let passphrase = prompt_passphrase(false)?;
            let imported = backup
                .decrypt_with_passphrase(&passphrase)
                .context("failed to decrypt backup")?;
            println!("Enter the vault seed phrase to unlock the destination vault.\n");
            let seed = prompt_seed(cli_seed)?;
            (imported, seed)
        }
        BackupSecretKind::Seed => {
            let seed = prompt_seed(cli_seed)?;
            let imported = backup
                .decrypt_with_seed(&seed)
                .context("failed to decrypt backup")?;
            (imported, seed)
        }
    };

    let count = imported.entries.len();
    let action = if merge {
        "Merge"
    } else {
        "Replace vault with"
    };
    if !yes
        && !Confirm::new()
            .with_prompt(format!(
                "{action} {count} entr{} from {}?",
                if count == 1 { "y" } else { "ies" },
                in_path.display()
            ))
            .default(false)
            .interact()?
    {
        bail!("aborted");
    }

    let mut vault = if vault_path.exists() {
        UnlockedVault::unlock(vault_path, &seed).context("failed to unlock vault")?
    } else {
        println!(
            "No vault at {}; creating one from the provided seed.\n",
            vault_path.display()
        );
        UnlockedVault::create(vault_path, &seed)?
    };

    if merge {
        merge_entries(&mut vault.data, imported);
    } else {
        vault.data = imported;
    }
    vault.persist()?;
    println!(
        "Imported into {} ({} entries).",
        vault_path.display(),
        vault.data.entries.len()
    );
    Ok(())
}
