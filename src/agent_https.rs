//! Fixed private GET consumer. Only trusted supervisor configuration supplies destinations.
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{DeliveryStatus, Error, Field, Fields};

const MAX_CREDENTIAL: usize = 8192;
// Fits the worst-case escaped URL, CA path, and two maximum-sized credentials
// without reallocating a buffer that has held plaintext.
const MAX_CONFIG: usize = 65_536;
const WALL_TIMEOUT: Duration = Duration::from_millis(3500);

// No Debug implementations on configuration, credentials, or the private child state.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    pub(crate) id: String,
    pub(crate) service: String,
    pub(crate) origin: String,
    pub(crate) path: String,
    pub(crate) auth: Auth,
    pub(crate) ca_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Auth {
    Basic,
    Bearer,
}

pub(crate) struct PreparedHttps {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    prefix: Zeroizing<String>,
    auth: Auth,
}

impl Destination {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.id.is_empty()
            || self.id.len() > 128
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || self.service.is_empty()
            || self.service.len() > 2048
            || !self.service.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || !valid_origin(&self.origin)
            || !valid_path(&self.path)
        {
            return Err(Error::Invalid);
        }
        if let Some(path) = &self.ca_file {
            validate_ca(path)?;
        }
        Ok(())
    }

    pub(crate) fn fields(&self) -> Fields {
        match self.auth {
            Auth::Basic => [Field::Username, Field::Password].into_iter().collect(),
            Auth::Bearer => [Field::ApiKey].into_iter().collect(),
        }
    }
}

fn valid_origin(origin: &str) -> bool {
    if origin.len() > 512 || !origin.is_ascii() {
        return false;
    }
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if let Some(port) = port {
        if port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|b| b.is_ascii_digit())
            || !port.parse::<u16>().is_ok_and(|p| p != 0)
        {
            return false;
        }
    }
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return host == ip.to_string();
    }
    // Curl accepts legacy numeric/hex/octal IPv4 spellings. Do not treat those as DNS.
    if host.split('.').all(|label| {
        (!label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
            || label
                .strip_prefix("0x")
                .or_else(|| label.strip_prefix("0X"))
                .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()))
    }) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn valid_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 2048 || !path.starts_with('/') || path.starts_with("//") {
        return false;
    }
    let bytes = path.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let b = bytes[offset];
        if b == b'%' {
            if offset + 2 >= bytes.len()
                || !bytes[offset + 1..offset + 3]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
            {
                return false;
            }
            offset += 3;
        } else if b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&b) {
            offset += 1;
        } else {
            return false;
        }
    }
    true
}

fn validate_ca(path: &Path) -> Result<(), Error> {
    let text = path.to_str().ok_or(Error::Invalid)?;
    if !path.is_absolute() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    // Trust the file and its whole path, not a symlink or a replaceable ancestor.
    let mut checked = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => checked.push(Path::new("/")),
            Component::Normal(name) => checked.push(name),
            _ => return Err(Error::Invalid),
        }
        let metadata = fs::symlink_metadata(&checked).map_err(|_| Error::Invalid)?;
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() };
        if metadata.file_type().is_symlink() || !trusted_owner || metadata.mode() & 0o022 != 0 {
            return Err(Error::Invalid);
        }
        let last = index + 1 == components.len();
        if (last && (!metadata.is_file() || metadata.len() == 0 || metadata.len() > 1_048_576))
            || (!last && !metadata.is_dir())
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

impl PreparedHttps {
    /// Call before use_secret. No URL or credentials reach the child until deliver.
    pub(crate) fn prepare(destination: &Destination) -> Result<Self, Error> {
        destination.validate()?;
        let mut prefix = Zeroizing::new(String::with_capacity(MAX_CONFIG));
        prefix.push_str("url = \"");
        push_escaped(&mut prefix, &destination.origin);
        push_escaped(&mut prefix, &destination.path);
        prefix.push_str("\"\n");
        if let Some(path) = &destination.ca_file {
            prefix.push_str("cacert = \"");
            push_escaped(&mut prefix, path.to_str().ok_or(Error::Invalid)?);
            prefix.push_str("\"\n");
        }
        let mut command = Command::new("/usr/bin/curl");
        command
            // -q must be first, before even --config, to disable every ambient curlrc.
            .args(["-q", "--config", "-"])
            .args([
                "--silent",
                "--globoff",
                "--path-as-is",
                "--request",
                "GET",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--no-location",
                "--no-location-trusted",
                "--max-redirs",
                "0",
                "--proxy",
                "",
                "--noproxy",
                "*",
                "--no-netrc",
                "--retry",
                "0",
                "--no-insecure",
                "--no-proxy-insecure",
                "--tlsv1.2",
                "--connect-timeout",
                "1",
                "--max-time",
                "2.5",
                "--basic",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: getpid has no arguments or memory-safety preconditions.
        let owner_pid = unsafe { libc::getpid() };
        // SAFETY: the child closure only invokes async-signal-safe system calls. Marking all
        // extra descriptors CLOEXEC also preserves Rust's private exec-error pipe until exec.
        unsafe {
            command.pre_exec(move || {
                if libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit) < 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) < 0
                    || libc::getppid() != owner_pid
                {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| Error::InteractionRequired)?;
        let mut prepared = Self {
            child: Some(child),
            input: None,
            output: None,
            prefix,
            auth: destination.auth,
        };
        let child = prepared.child.as_mut().ok_or(Error::InteractionRequired)?;
        prepared.input = child.stdin.take();
        prepared.output = child.stdout.take();
        let input = prepared
            .input
            .as_ref()
            .ok_or(Error::InteractionRequired)?
            .as_raw_fd();
        let output = prepared
            .output
            .as_ref()
            .ok_or(Error::InteractionRequired)?
            .as_raw_fd();
        for fd in [input, output] {
            nonblocking_cloexec(fd).map_err(|_| Error::InteractionRequired)?;
        }
        Ok(prepared)
    }

    /// Trusted final-handoff callback only. Generic HTTP success is not verified login/signup.
    pub(crate) fn deliver(
        mut self,
        values: &BTreeMap<Field, &str>,
    ) -> Result<DeliveryStatus, Error> {
        append_auth(&mut self.prefix, self.auth, values)?;
        let deadline = Instant::now() + WALL_TIMEOUT;
        let mut sent = 0;
        let mut status_bytes = [0u8; 4];
        let mut received = 0;
        let mut eof = false;
        let mut exit = None;
        loop {
            if Instant::now() >= deadline {
                return Ok(DeliveryStatus::Unknown);
            }
            // Write immediately after validation/escaping, never queue or spawn at handoff.
            if let Some(input) = self.input.as_mut() {
                match input.write(&self.prefix.as_bytes()[sent..]) {
                    Ok(0) => return Ok(DeliveryStatus::Unknown),
                    Ok(count) => sent += count,
                    Err(error) if transient(&error) => {}
                    Err(_) => return Ok(DeliveryStatus::Unknown),
                }
                if sent == self.prefix.len() {
                    self.input.take(); // EOF tells curl it has the complete private configuration.
                    self.prefix.zeroize();
                }
            }
            if !eof {
                let Some(output) = self.output.as_mut() else {
                    return Ok(DeliveryStatus::Unknown);
                };
                match output.read(&mut status_bytes[received..]) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        received += count;
                        if received == status_bytes.len() {
                            return Ok(DeliveryStatus::Unknown);
                        }
                    }
                    Err(error) if transient(&error) => {}
                    Err(_) => return Ok(DeliveryStatus::Unknown),
                }
            }
            if exit.is_none() {
                exit = match self
                    .child
                    .as_mut()
                    .ok_or(Error::InteractionRequired)?
                    .try_wait()
                {
                    Ok(status) => status,
                    Err(_) => return Ok(DeliveryStatus::Unknown),
                };
            }
            if let Some(status) = exit {
                if eof {
                    self.child.take(); // try_wait already reaped this child.
                    return Ok(map_status(status.success(), &status_bytes[..received]));
                }
            }
            let mut polls = [
                libc::pollfd {
                    fd: self.input.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if eof {
                        -1
                    } else {
                        self.output.as_ref().map_or(-1, AsRawFd::as_raw_fd)
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(25) as i32;
            // SAFETY: polls is an initialized array of the given length; no other thread uses it.
            if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, wait) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                return Ok(DeliveryStatus::Unknown);
            }
        }
    }
}

impl Drop for PreparedHttps {
    fn drop(&mut self) {
        self.input.take();
        self.output.take();
        if let Some(mut child) = self.child.take() {
            // SIGKILL, not a graceful shutdown that can wait on a blocked transfer or stdin.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn nonblocking_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: these fcntl commands only inspect/set flags on this live owned descriptor.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0
            || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
            || libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn push_escaped(output: &mut String, value: &str) {
    for c in value.chars() {
        if c == '\\' || c == '"' {
            output.push('\\');
        }
        output.push(c);
    }
}

fn valid_basic(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CREDENTIAL && !value.chars().any(char::is_control)
}

fn valid_bearer(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CREDENTIAL {
        return false;
    }
    let token = value.trim_end_matches('=');
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

fn append_auth(
    output: &mut String,
    auth: Auth,
    values: &BTreeMap<Field, &str>,
) -> Result<(), Error> {
    match auth {
        Auth::Basic => {
            if values.len() != 2 {
                return Err(Error::Invalid);
            }
            let username = values.get(&Field::Username).ok_or(Error::Invalid)?;
            let password = values.get(&Field::Password).ok_or(Error::Invalid)?;
            if !valid_basic(username) || username.contains(':') || !valid_basic(password) {
                return Err(Error::Invalid);
            }
            output.push_str("user = \"");
            push_escaped(output, username);
            output.push(':');
            push_escaped(output, password);
            output.push_str("\"\n");
        }
        Auth::Bearer => {
            if values.len() != 1 {
                return Err(Error::Invalid);
            }
            let token = values.get(&Field::ApiKey).ok_or(Error::Invalid)?;
            if !valid_bearer(token) {
                return Err(Error::Invalid);
            }
            output.push_str("header = \"Authorization: Bearer ");
            push_escaped(output, token);
            output.push_str("\"\n");
        }
    }
    if output.len() > MAX_CONFIG {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn map_status(success: bool, bytes: &[u8]) -> DeliveryStatus {
    if !success || bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return DeliveryStatus::Unknown;
    }
    match bytes[0] {
        b'2' => DeliveryStatus::Accepted,
        b'3' | b'4' => DeliveryStatus::Rejected,
        _ => DeliveryStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn destination(auth: Auth) -> Destination {
        Destination {
            id: "fixture".into(),
            service: "fixture".into(),
            origin: "https://localhost:443".into(),
            path: "/private".into(),
            auth,
            ca_file: None,
        }
    }

    #[test]
    fn exact_destination_and_fields() {
        assert!(destination(Auth::Basic).validate().is_ok());
        assert_eq!(
            destination(Auth::Basic).fields(),
            [Field::Username, Field::Password].into_iter().collect()
        );
        assert_eq!(
            destination(Auth::Bearer).fields(),
            [Field::ApiKey].into_iter().collect()
        );
        for origin in [
            "http://localhost",
            "https://user@localhost",
            "https://localhost/",
            "https://localhost?x",
            "https://localhost#x",
            "https://localhost\\evil",
            "https://[::1]",
            "https://localhost:0",
            "https://localhost:65536",
            "https://localhost:\n443",
            "https://127.1",
            "https://0x7f000001",
            "https://0177.0.0.1",
            "https://localhost..",
            "https://-localhost",
            "https://é.test",
        ] {
            let mut d = destination(Auth::Basic);
            d.origin = origin.into();
            assert!(d.validate().is_err());
        }
        for path in [
            "//elsewhere",
            "relative",
            "/bad\nheader",
            "/bad\\path",
            "/bad\"path",
            "/?query",
            "/#fragment",
            "/%",
            "/%0x",
        ] {
            let mut d = destination(Auth::Basic);
            d.path = path.into();
            assert!(d.validate().is_err());
        }
        assert!(valid_origin("https://127.0.0.1:8443"));
        assert!(valid_path("/fixed/a%20b"));
    }

    #[test]
    fn private_configuration_escaping_and_exact_fields() {
        let mut config = Zeroizing::new(String::new());
        let values = BTreeMap::from([
            (Field::Username, "synthetic\"user"),
            (Field::Password, "synthetic\\password"),
        ]);
        assert!(append_auth(&mut config, Auth::Basic, &values).is_ok());
        assert_eq!(
            config.as_str(),
            "user = \"synthetic\\\"user:synthetic\\\\password\"\n"
        );
        for bad in ["x\nurl = https://elsewhere", "x\rheader", "x\0", "x\u{7f}"] {
            let values = BTreeMap::from([(Field::Username, "synthetic"), (Field::Password, bad)]);
            assert!(append_auth(&mut Zeroizing::new(String::new()), Auth::Basic, &values).is_err());
        }
        let extra = BTreeMap::from([
            (Field::Username, "synthetic"),
            (Field::Password, "synthetic"),
            (Field::Notes, "extra"),
        ]);
        assert!(append_auth(&mut String::new(), Auth::Basic, &extra).is_err());
        for bad in ["x y", "x\nX-Header: injected", "x\"", "x\\", "=", "x=y"] {
            assert!(!valid_bearer(bad));
        }
        assert!(valid_bearer("synthetic-._~+/=="));
        let mut bearer = Zeroizing::new(String::with_capacity(MAX_CONFIG));
        let values = BTreeMap::from([(Field::ApiKey, "synthetic-token")]);
        assert!(append_auth(&mut bearer, Auth::Bearer, &values).is_ok());
        assert_eq!(
            bearer.as_str(),
            concat!("header = \"Authorization: ", "Bearer synthetic-token\"\n")
        );
        let mut maximum = Zeroizing::new(String::with_capacity(MAX_CONFIG));
        maximum.push_str(&"x".repeat(11_000));
        let capacity = maximum.capacity();
        let credential = Zeroizing::new("\\".repeat(MAX_CREDENTIAL));
        let values = BTreeMap::from([
            (Field::Username, credential.as_str()),
            (Field::Password, credential.as_str()),
        ]);
        assert!(append_auth(&mut maximum, Auth::Basic, &values).is_ok());
        assert_eq!(maximum.capacity(), capacity);
        maximum.zeroize();
        assert!(maximum.is_empty());
    }

    #[test]
    fn status_is_strict_and_transport_failures_are_unknown() {
        assert_eq!(map_status(true, b"204"), DeliveryStatus::Accepted);
        assert_eq!(map_status(true, b"302"), DeliveryStatus::Rejected);
        assert_eq!(map_status(true, b"401"), DeliveryStatus::Rejected);
        for bytes in [
            b"000".as_slice(),
            b"500",
            b"200\n",
            b"20",
            b"2x0",
            b"secret",
        ] {
            assert_eq!(map_status(true, bytes), DeliveryStatus::Unknown);
        }
        assert_eq!(map_status(false, b"200"), DeliveryStatus::Unknown);
    }

    #[test]
    fn destination_rejects_unrecognized_configuration() {
        let json = r#"{"id":"fixture","service":"fixture","origin":"https://localhost","path":"/","auth":"bearer","proxy":"http://elsewhere"}"#;
        assert!(serde_json::from_str::<Destination>(json).is_err());
    }
}
