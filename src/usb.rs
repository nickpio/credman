//! Linux USB hardware-key helpers: portable stick layout and auto-launch watcher.
//!
//! The encrypted vault lives on a volume labeled `CREDMAN`. A one-time user-level
//! systemd poller opens a terminal with credman when the stick is inserted. The
//! BIP39 seed still unlocks the vault (possession + knowledge).

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

pub const VOLUME_LABEL: &str = "CREDMAN";
const VAULT_NAME: &str = "vault";
const README_NAME: &str = "CREDMAN.txt";
const BIN_DIR: &str = "bin";
const BIN_NAME: &str = "credman";

const LAUNCH_SCRIPT: &str = "usb-launch.sh";
const WATCH_SCRIPT: &str = "usb-watch.sh";
const SERVICE_NAME: &str = "credman-usb.service";

/// Discover the mount point of a filesystem labeled `CREDMAN`.
pub fn find_credman_mount() -> Result<Option<PathBuf>> {
    find_credman_mount_with(|dev| findmnt_target(dev), label_device_path())
}

fn label_device_path() -> PathBuf {
    PathBuf::from(format!("/dev/disk/by-label/{VOLUME_LABEL}"))
}

fn find_credman_mount_with<F>(findmnt: F, label_link: PathBuf) -> Result<Option<PathBuf>>
where
    F: FnOnce(&Path) -> Result<Option<PathBuf>>,
{
    if !label_link.exists() {
        return Ok(None);
    }
    let device = fs::canonicalize(&label_link).unwrap_or(label_link);
    findmnt(&device)
}

fn findmnt_target(device: &Path) -> Result<Option<PathBuf>> {
    let output = Command::new("findmnt")
        .args(["-n", "-o", "TARGET", "--source"])
        .arg(device)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return find_mount_from_proc(device);
        }
        Err(e) => return Err(e).context("failed to run findmnt"),
    };

    if !output.status.success() {
        return find_mount_from_proc(device);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(line)))
}

fn find_mount_from_proc(device: &Path) -> Result<Option<PathBuf>> {
    let mounts = fs::read_to_string("/proc/self/mounts").context("failed to read /proc/self/mounts")?;
    let device_str = device.to_string_lossy();
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let Some(src) = parts.next() else { continue };
        let Some(target) = parts.next() else { continue };
        if src == device_str {
            return Ok(Some(PathBuf::from(unescape_mount(target))));
        }
    }
    Ok(None)
}

fn unescape_mount(s: &str) -> String {
    // /proc/mounts escapes space as \040, tab as \011, etc.
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let code: String = (0..3).filter_map(|_| chars.next()).collect();
            if let Ok(n) = u8::from_str_radix(&code, 8) {
                out.push(n as char);
            } else {
                out.push('\\');
                out.push_str(&code);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Vault path on a CREDMAN stick mount.
pub fn vault_on_mount(mount: &Path) -> PathBuf {
    mount.join(VAULT_NAME)
}

/// Prefer host `credman` on PATH; otherwise `$mount/bin/credman`.
pub fn resolve_credman_binary(mount: &Path) -> Option<PathBuf> {
    resolve_credman_binary_with(mount, which_credman)
}

fn which_credman() -> Option<PathBuf> {
    let output = Command::new("sh")
        .args(["-c", "command -v credman"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn resolve_credman_binary_with<F>(mount: &Path, host_which: F) -> Option<PathBuf>
where
    F: FnOnce() -> Option<PathBuf>,
{
    if let Some(host) = host_which() {
        return Some(host);
    }
    let portable = mount.join(BIN_DIR).join(BIN_NAME);
    if portable.is_file() {
        Some(portable)
    } else {
        None
    }
}

fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not determine config directory")?;
    Ok(base.join("credman"))
}

fn systemd_user_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not determine config directory")?;
    Ok(base.join("systemd").join("user"))
}

fn current_exe_path() -> Result<PathBuf> {
    env::current_exe().context("could not determine current executable path")
}

/// Prepare a mounted stick: vault, optional portable binary, and README.
pub fn prepare(mount: &Path, source_vault: Option<&Path>, force: bool) -> Result<PrepareReport> {
    if !mount.is_dir() {
        bail!("mount path is not a directory: {}", mount.display());
    }

    let dest_vault = vault_on_mount(mount);
    let mut copied_vault = false;
    let mut needs_init = false;

    match source_vault {
        Some(src) => {
            if !src.exists() {
                bail!("source vault does not exist: {}", src.display());
            }
            if dest_vault.exists() && !force {
                bail!(
                    "vault already exists at {} (pass --force to overwrite)",
                    dest_vault.display()
                );
            }
            fs::copy(src, &dest_vault).with_context(|| {
                format!(
                    "failed to copy vault from {} to {}",
                    src.display(),
                    dest_vault.display()
                )
            })?;
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&dest_vault, fs::Permissions::from_mode(0o600));
            }
            copied_vault = true;
        }
        None => {
            if force && dest_vault.exists() {
                fs::remove_file(&dest_vault)
                    .with_context(|| format!("failed to remove {}", dest_vault.display()))?;
            }
            if !dest_vault.exists() {
                needs_init = true;
            }
        }
    }

    let bin_dir = mount.join(BIN_DIR);
    fs::create_dir_all(&bin_dir)
        .with_context(|| format!("failed to create {}", bin_dir.display()))?;

    let mut copied_binary = false;
    let exe = current_exe_path()?;
    let dest_bin = bin_dir.join(BIN_NAME);
    if exe.exists() {
        fs::copy(&exe, &dest_bin).with_context(|| {
            format!(
                "failed to copy binary from {} to {}",
                exe.display(),
                dest_bin.display()
            )
        })?;
        #[cfg(unix)]
        fs::set_permissions(&dest_bin, fs::Permissions::from_mode(0o755))?;
        copied_binary = true;
    }

    let readme = mount.join(README_NAME);
    fs::write(&readme, readme_contents()).with_context(|| {
        format!("failed to write {}", readme.display())
    })?;

    Ok(PrepareReport {
        mount: mount.to_path_buf(),
        vault: dest_vault,
        copied_vault,
        copied_binary,
        needs_init,
    })
}

#[derive(Debug)]
pub struct PrepareReport {
    pub mount: PathBuf,
    pub vault: PathBuf,
    pub copied_vault: bool,
    pub copied_binary: bool,
    pub needs_init: bool,
}

fn readme_contents() -> String {
    format!(
        r#"credman USB hardware key
========================

This stick should be labeled "{VOLUME_LABEL}" (filesystem label).

Layout:
  vault          encrypted credential vault
  bin/credman    portable Linux binary (optional if credman is installed on the host)
  {README_NAME}  this file

Unlock:
  1. Mount this stick
  2. Run:  credman --vault /path/to/this/stick/vault
     or:   /path/to/this/stick/bin/credman --vault /path/to/this/stick/vault
  3. Enter your 12-word seed phrase

Auto-launch on insert (Linux, one-time per machine):
  credman usb enable

Label the filesystem (pick one matching your FS):
  fatlabel /dev/sdX1 {VOLUME_LABEL}
  exfatlabel /dev/sdX1 {VOLUME_LABEL}
  e2label /dev/sdX1 {VOLUME_LABEL}

Possession of this stick + knowledge of the seed unlocks the vault.
The seed is never stored on the stick.
"#
    )
}

fn launch_script_contents() -> String {
    format!(
        r#"#!/bin/sh
# Auto-generated by `credman usb enable`. Opens credman for a CREDMAN-labeled stick.
set -eu

LABEL="{VOLUME_LABEL}"
STATE_DIR="${{XDG_STATE_HOME:-$HOME/.local/state}}/credman"
mkdir -p "$STATE_DIR"

label_link="/dev/disk/by-label/$LABEL"
if [ ! -e "$label_link" ]; then
  exit 0
fi

device="$(readlink -f "$label_link" 2>/dev/null || echo "$label_link")"
mount=""
if command -v findmnt >/dev/null 2>&1; then
  mount="$(findmnt -n -o TARGET --source "$device" 2>/dev/null | head -n1 || true)"
fi
if [ -z "$mount" ] && [ -r /proc/self/mounts ]; then
  mount="$(awk -v d="$device" '$1 == d {{ print $2; exit }}' /proc/self/mounts || true)"
fi
if [ -z "$mount" ] || [ ! -d "$mount" ]; then
  exit 0
fi

vault="$mount/{VAULT_NAME}"
if [ ! -f "$vault" ]; then
  exit 0
fi

# Skip if another credman session already holds the vault lock.
if command -v fuser >/dev/null 2>&1; then
  if fuser "${{vault}}.lock" >/dev/null 2>&1; then
    exit 0
  fi
fi

bin=""
if command -v credman >/dev/null 2>&1; then
  bin="$(command -v credman)"
elif [ -x "$mount/{BIN_DIR}/{BIN_NAME}" ]; then
  bin="$mount/{BIN_DIR}/{BIN_NAME}"
else
  exit 0
fi

pick_term() {{
  if [ -n "${{TERMINAL:-}}" ] && command -v "$TERMINAL" >/dev/null 2>&1; then
    echo "$TERMINAL"
    return
  fi
  for t in x-terminal-emulator gnome-terminal konsole alacritty kitty xfce4-terminal tilix mate-terminal; do
    if command -v "$t" >/dev/null 2>&1; then
      echo "$t"
      return
    fi
  done
  return 1
}}

term="$(pick_term || true)"
if [ -z "$term" ]; then
  # No graphical terminal — try running directly (best effort).
  exec "$bin" --vault "$vault"
fi

case "$term" in
  gnome-terminal|mate-terminal|tilix)
    exec "$term" -- "$bin" --vault "$vault"
    ;;
  konsole)
    exec "$term" -e "$bin --vault $vault"
    ;;
  *)
    exec "$term" -e "$bin" --vault "$vault"
    ;;
esac
"#
    )
}

fn watch_script_contents(launch_path: &Path) -> String {
    format!(
        r#"#!/bin/sh
# Auto-generated by `credman usb enable`. Polls for CREDMAN stick insert.
set -eu

LABEL="{VOLUME_LABEL}"
STATE_DIR="${{XDG_STATE_HOME:-$HOME/.local/state}}/credman"
mkdir -p "$STATE_DIR"
LAST_FILE="$STATE_DIR/usb-last-device"
LAUNCH="{launch}"

last=""
if [ -f "$LAST_FILE" ]; then
  last="$(cat "$LAST_FILE" 2>/dev/null || true)"
fi

while true; do
  label_link="/dev/disk/by-label/$LABEL"
  if [ -e "$label_link" ]; then
    device="$(readlink -f "$label_link" 2>/dev/null || echo "$label_link")"
    if [ "$device" != "$last" ]; then
      # Wait briefly for automount.
      i=0
      while [ "$i" -lt 20 ]; do
        mount=""
        if command -v findmnt >/dev/null 2>&1; then
          mount="$(findmnt -n -o TARGET --source "$device" 2>/dev/null | head -n1 || true)"
        fi
        if [ -n "$mount" ] && [ -d "$mount" ]; then
          break
        fi
        i=$((i + 1))
        sleep 0.5
      done
      # Debounce: record device before launch so remount noise does not re-fire.
      echo "$device" > "$LAST_FILE"
      last="$device"
      sh "$LAUNCH" || true
    fi
  else
    if [ -n "$last" ]; then
      last=""
      rm -f "$LAST_FILE"
    fi
  fi
  sleep 2
done
"#,
        launch = launch_path.display()
    )
}

fn service_unit_contents(watch_path: &Path) -> String {
    format!(
        r#"[Unit]
Description=credman USB hardware-key watcher (CREDMAN label)
After=default.target

[Service]
Type=simple
ExecStart=/bin/sh {watch}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"#,
        watch = watch_path.display()
    )
}

/// Install user-level auto-launch helper (systemd poller + scripts).
pub fn enable() -> Result<EnableReport> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("credman usb enable is only supported on Linux");
    }
    #[cfg(target_os = "linux")]
    {
        enable_linux()
    }
}

#[cfg(target_os = "linux")]
fn enable_linux() -> Result<EnableReport> {
    let cfg = config_dir()?;
    fs::create_dir_all(&cfg).with_context(|| format!("failed to create {}", cfg.display()))?;

    let launch_path = cfg.join(LAUNCH_SCRIPT);
    let watch_path = cfg.join(WATCH_SCRIPT);
    fs::write(&launch_path, launch_script_contents())?;
    fs::write(&watch_path, watch_script_contents(&launch_path))?;
    fs::set_permissions(&launch_path, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&watch_path, fs::Permissions::from_mode(0o755))?;

    let systemd_dir = systemd_user_dir()?;
    fs::create_dir_all(&systemd_dir)
        .with_context(|| format!("failed to create {}", systemd_dir.display()))?;
    let service_path = systemd_dir.join(SERVICE_NAME);
    fs::write(&service_path, service_unit_contents(&watch_path))?;

    let mut systemd_ok = false;
    let systemd_message;

    let reload = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();
    match reload {
        Ok(o) if o.status.success() => {
            let enable = Command::new("systemctl")
                .args(["--user", "enable", "--now", SERVICE_NAME])
                .output()
                .context("failed to enable credman-usb.service")?;
            if enable.status.success() {
                systemd_ok = true;
                systemd_message = format!("{SERVICE_NAME} enabled and started");
            } else {
                systemd_message = format!(
                    "wrote unit but enable failed: {}",
                    String::from_utf8_lossy(&enable.stderr).trim()
                );
            }
        }
        Ok(o) => {
            systemd_message = format!(
                "wrote files but systemctl daemon-reload failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        Err(e) => {
            systemd_message = format!(
                "wrote files but systemctl is unavailable ({e}); start manually: sh {}",
                watch_path.display()
            );
        }
    }

    Ok(EnableReport {
        launch_path,
        watch_path,
        service_path,
        systemd_ok,
        systemd_message,
    })
}

pub struct EnableReport {
    pub launch_path: PathBuf,
    pub watch_path: PathBuf,
    pub service_path: PathBuf,
    pub systemd_ok: bool,
    pub systemd_message: String,
}

/// Remove auto-launch helper files and disable the user service.
pub fn disable() -> Result<DisableReport> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("credman usb disable is only supported on Linux");
    }
    #[cfg(target_os = "linux")]
    {
        disable_linux()
    }
}

#[cfg(target_os = "linux")]
fn disable_linux() -> Result<DisableReport> {
    let mut messages = Vec::new();

    let stop = Command::new("systemctl")
        .args(["--user", "disable", "--now", SERVICE_NAME])
        .output();
    match stop {
        Ok(o) if o.status.success() => messages.push(format!("{SERVICE_NAME} stopped and disabled")),
        Ok(o) => messages.push(format!(
            "systemctl disable: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => messages.push(format!("systemctl unavailable: {e}")),
    }

    let mut removed = Vec::new();
    if let Ok(cfg) = config_dir() {
        for name in [LAUNCH_SCRIPT, WATCH_SCRIPT] {
            let p = cfg.join(name);
            if p.exists() {
                fs::remove_file(&p)?;
                removed.push(p);
            }
        }
    }
    if let Ok(systemd_dir) = systemd_user_dir() {
        let p = systemd_dir.join(SERVICE_NAME);
        if p.exists() {
            fs::remove_file(&p)?;
            removed.push(p);
        }
    }

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    if let Some(state) = dirs::state_dir() {
        let last = state.join("credman").join("usb-last-device");
        if last.exists() {
            let _ = fs::remove_file(&last);
        }
    }

    Ok(DisableReport { removed, messages })
}

pub struct DisableReport {
    pub removed: Vec<PathBuf>,
    pub messages: Vec<String>,
}

/// Status of helper install and any mounted CREDMAN volume.
pub fn status() -> Result<UsbStatus> {
    let helper_installed = helper_installed();
    let mount = find_credman_mount()?;
    let vault = mount.as_ref().map(|m| vault_on_mount(m));
    let vault_exists = vault.as_ref().is_some_and(|p| p.exists());
    let binary = mount.as_ref().and_then(|m| resolve_credman_binary(m));

    let service_active = {
        let out = Command::new("systemctl")
            .args(["--user", "is-active", SERVICE_NAME])
            .output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim() == "active",
            Err(_) => false,
        }
    };

    Ok(UsbStatus {
        helper_installed,
        service_active,
        mount,
        vault,
        vault_exists,
        binary,
    })
}

fn helper_installed() -> bool {
    let Ok(cfg) = config_dir() else {
        return false;
    };
    let Ok(systemd_dir) = systemd_user_dir() else {
        return false;
    };
    cfg.join(LAUNCH_SCRIPT).is_file()
        && cfg.join(WATCH_SCRIPT).is_file()
        && systemd_dir.join(SERVICE_NAME).is_file()
}

pub struct UsbStatus {
    pub helper_installed: bool,
    pub service_active: bool,
    pub mount: Option<PathBuf>,
    pub vault: Option<PathBuf>,
    pub vault_exists: bool,
    pub binary: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn find_credman_mount_missing_label_returns_none() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-label");
        let result = find_credman_mount_with(|_| Ok(None), missing).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn find_credman_mount_uses_findmnt() {
        let dir = tempdir().unwrap();
        let link = dir.path().join("CREDMAN");
        File::create(&link).unwrap();
        let mount = dir.path().join("mnt");
        fs::create_dir(&mount).unwrap();
        let mount_clone = mount.clone();
        let result =
            find_credman_mount_with(move |_| Ok(Some(mount_clone)), link).unwrap();
        assert_eq!(result.unwrap(), mount);
    }

    #[test]
    fn resolve_prefers_host_binary() {
        let dir = tempdir().unwrap();
        let mount = dir.path();
        let portable = mount.join(BIN_DIR);
        fs::create_dir_all(&portable).unwrap();
        let portable_bin = portable.join(BIN_NAME);
        File::create(&portable_bin).unwrap();

        let host = PathBuf::from("/usr/bin/credman");
        let resolved = resolve_credman_binary_with(mount, || Some(host.clone()));
        assert_eq!(resolved, Some(host));
    }

    #[test]
    fn resolve_falls_back_to_portable() {
        let dir = tempdir().unwrap();
        let mount = dir.path();
        let portable = mount.join(BIN_DIR);
        fs::create_dir_all(&portable).unwrap();
        let portable_bin = portable.join(BIN_NAME);
        File::create(&portable_bin).unwrap();

        let resolved = resolve_credman_binary_with(mount, || None);
        assert_eq!(resolved, Some(portable_bin));
    }

    #[test]
    fn resolve_none_when_missing() {
        let dir = tempdir().unwrap();
        let resolved = resolve_credman_binary_with(dir.path(), || None);
        assert!(resolved.is_none());
    }

    #[test]
    fn prepare_copies_vault_and_writes_readme() {
        let dir = tempdir().unwrap();
        let mount = dir.path().join("stick");
        fs::create_dir(&mount).unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let src_vault = src_dir.join("vault");
        fs::write(&src_vault, b"fake-vault-bytes").unwrap();

        // current_exe exists in tests; prepare will try to copy it.
        let report = prepare(&mount, Some(&src_vault), false).unwrap();
        assert!(report.copied_vault);
        assert!(report.vault.exists());
        assert_eq!(fs::read(&report.vault).unwrap(), b"fake-vault-bytes");
        assert!(mount.join(README_NAME).exists());
        assert!(mount.join(BIN_DIR).join(BIN_NAME).exists() || !report.copied_binary);
        assert!(!report.needs_init);
    }

    #[test]
    fn prepare_refuses_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let mount = dir.path().join("stick");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join(VAULT_NAME), b"existing").unwrap();

        let src = dir.path().join("other");
        fs::write(&src, b"new").unwrap();
        let err = prepare(&mount, Some(&src), false).unwrap_err();
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn prepare_force_overwrites_vault() {
        let dir = tempdir().unwrap();
        let mount = dir.path().join("stick");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join(VAULT_NAME), b"old").unwrap();

        let src = dir.path().join("other");
        fs::write(&src, b"new").unwrap();
        let report = prepare(&mount, Some(&src), true).unwrap();
        assert!(report.copied_vault);
        assert_eq!(fs::read(mount.join(VAULT_NAME)).unwrap(), b"new");
    }

    #[test]
    fn prepare_without_source_leaves_needs_init() {
        let dir = tempdir().unwrap();
        let mount = dir.path().join("stick");
        fs::create_dir(&mount).unwrap();
        let report = prepare(&mount, None, false).unwrap();
        assert!(!report.copied_vault);
        assert!(report.needs_init);
        assert!(!report.vault.exists());
        assert!(mount.join(README_NAME).is_file());
    }

    #[test]
    fn unescape_mount_spaces() {
        assert_eq!(unescape_mount(r"/media/user/My\040Stick"), "/media/user/My Stick");
    }

    #[test]
    fn vault_on_mount_joins_name() {
        assert_eq!(
            vault_on_mount(Path::new("/media/stick")),
            PathBuf::from("/media/stick/vault")
        );
    }
}
