use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;
use zeroize::Zeroizing;

pub const CLIPBOARD_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error(transparent)]
    Clipboard(#[from] arboard::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearOutcome {
    Cleared,
    Changed,
}

pub enum HelperSchedule {
    Scheduled,
    Unavailable(io::Error),
}

pub struct PendingClipboard {
    secret: Zeroizing<String>,
    expires_at: Instant,
}

impl PendingClipboard {
    pub fn copy(secret: &str) -> Result<Self, ClipboardError> {
        let mut clipboard = arboard::Clipboard::new()?;
        clipboard.set_text(secret.to_string())?;
        Ok(Self {
            secret: Zeroizing::new(secret.to_string()),
            expires_at: Instant::now() + CLIPBOARD_TTL,
        })
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn remaining_seconds(&self) -> u64 {
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)
    }

    pub fn clear_if_unchanged(&self) -> Result<ClearOutcome, ClipboardError> {
        clear_if_unchanged(&self.secret)
    }
}

pub fn copy_with_helper(secret: &str) -> Result<HelperSchedule, ClipboardError> {
    let pending = PendingClipboard::copy(secret)?;
    Ok(match spawn_clear_helper(&pending.secret) {
        Ok(()) => HelperSchedule::Scheduled,
        Err(error) => HelperSchedule::Unavailable(error),
    })
}

pub fn run_clear_helper() -> Result<(), ClipboardError> {
    let mut secret = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut secret)?;
    std::thread::sleep(CLIPBOARD_TTL);
    let _ = clear_if_unchanged(&secret)?;
    Ok(())
}

fn spawn_clear_helper(secret: &str) -> io::Result<()> {
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("clipboard-clear")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "clipboard helper stdin unavailable",
        )
    })?;
    stdin.write_all(secret.as_bytes())
}

fn clear_if_unchanged(expected: &str) -> Result<ClearOutcome, ClipboardError> {
    let mut clipboard = arboard::Clipboard::new()?;
    let current = clipboard.get_text()?;
    if should_clear(&current, expected) {
        clipboard.set_text(String::new())?;
        Ok(ClearOutcome::Cleared)
    } else {
        Ok(ClearOutcome::Changed)
    }
}

fn should_clear(current: &str, expected: &str) -> bool {
    current == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_before_clear_only_matches_original_secret() {
        assert!(should_clear("secret", "secret"));
        assert!(!should_clear("new clipboard value", "secret"));
    }

    #[test]
    fn remaining_seconds_rounds_up() {
        let pending = PendingClipboard {
            secret: Zeroizing::new("secret".into()),
            expires_at: Instant::now() + Duration::from_millis(1_100),
        };

        assert_eq!(pending.remaining_seconds(), 2);
        assert!(!pending.is_expired());
    }
}
