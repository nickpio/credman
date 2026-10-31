use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::agent::Error;

pub(crate) struct StartupFailure {
    command: &'static str,
    error: Error,
}

impl StartupFailure {
    pub(crate) fn report(&self) -> String {
        let (command, error) = (self.command, self.error);
        format!("credman {command}: {error}")
    }
    /// Stable process statuses. 0 is success. The command parser uses its own status for usage errors.
    pub(crate) fn code(&self) -> i32 { exit_code(self.error) }
}

fn exit_code(error: Error) -> i32 {
    match error {
        Error::Denied => 10,
        Error::Invalid => 11,
        Error::Conflict => 12,
        Error::ReplayConflict => 13,
        Error::ClockRecoveryRequired => 14,
        Error::Capacity => 15,
        Error::InteractionRequired => 16,
        Error::GenerationUnavailable => 17,
        Error::NotPublished => 18,
        Error::RecoveryRequired => 19,
        Error::InvalidStorage => 20,
        Error::InUse => 21,
    }
}

fn fail(command: &'static str, error: Error) -> StartupFailure { StartupFailure { command, error } }

#[derive(Parser, Debug)]
#[command(name = "credman", about = "Agent-native credential vault with scoped sharing and private HTTPS use")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Serve trusted preconnected supervisor channels (Linux)
    Serve {
        #[arg(long)]
        directory: PathBuf,
        /// Exclusively transferred seed descriptor, never argv
        #[arg(long)]
        seed_fd: i32,
        /// Trusted supervisor configuration descriptor
        #[arg(long)]
        config_fd: i32,
        /// Separate connected human administration channel
        #[arg(long)]
        admin_fd: i32,
        /// Initialize a dedicated private directory without replacing state
        #[arg(long)]
        create: bool,
        /// Private supervisor-owned Unix socket for bounded MCP session admission
        #[arg(long)]
        bridge_socket: Option<PathBuf>,
    },
    /// Serve MCP stdio using a supervisor-issued private session file
    Mcp {
        #[arg(long)]
        session_file: PathBuf,
    },
    /// Offline trusted-human administration using private descriptors (Linux)
    Admin {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        seed_fd: i32,
        #[arg(long)]
        identity_fd: i32,
        #[command(subcommand)]
        operation: AdminCommands,
    },
}

#[derive(Subcommand, Debug)]
enum AdminCommands {
    Backup {
        #[arg(long)]
        secret_fd: i32,
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        output_fd: i32,
    },
    Restore {
        #[arg(long)]
        secret_fd: i32,
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        backup_fd: i32,
    },
    Recover,
}

pub(crate) fn run() -> Result<(), StartupFailure> {
    match Cli::parse().command {
        Commands::Admin { directory, seed_fd, identity_fd, operation } => {
            let operation = match operation {
                AdminCommands::Backup { secret_fd, passphrase, output_fd } =>
                    crate::agent_admin::Operation::Backup { secret_fd, passphrase, output_fd },
                AdminCommands::Restore { secret_fd, passphrase, backup_fd } =>
                    crate::agent_admin::Operation::Restore { secret_fd, passphrase, backup_fd },
                AdminCommands::Recover => crate::agent_admin::Operation::Recover,
            };
            crate::agent_admin::run(crate::agent_admin::Options { directory, seed_fd, identity_fd, operation })
                .map_err(|error| fail("admin", error))
        }
        Commands::Serve { directory, seed_fd, config_fd, admin_fd, create, bridge_socket } => {
            let options = crate::agent_broker::RunOptions { directory, seed_fd, config_fd, admin_fd, create, bridge_socket };
            crate::agent_broker::run(options).map_err(|error| fail("serve", error))
        }
        Commands::Mcp { session_file } => crate::agent_mcp::run(&session_file).map_err(|error| fail("mcp", error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn supported_commands_and_descriptor_options_are_accepted() {
        let command = Cli::command();
        assert_eq!(command.get_subcommands().map(|c| c.get_name()).collect::<Vec<_>>(),
            ["serve", "mcp", "admin"]);
        assert_eq!(command.find_subcommand("admin").unwrap().get_subcommands()
            .map(|c| c.get_name()).collect::<Vec<_>>(), ["backup", "restore", "recover"]);
        assert!(Cli::try_parse_from(["credman", "serve", "--directory", "synthetic", "--seed-fd", "3",
            "--config-fd", "4", "--admin-fd", "5", "--create"]).is_ok());
        assert!(Cli::try_parse_from(["credman", "serve", "--directory", "synthetic", "--seed-fd", "3",
            "--config-fd", "4", "--admin-fd", "5", "--bridge-socket", "/private/bridge.sock"]).is_ok());
        assert!(Cli::try_parse_from(["credman", "mcp", "--session-file", "/private/session.json"]).is_ok());
        assert!(Cli::try_parse_from(["credman", "mcp", "--seed-fd", "3"]).is_err());
        assert!(Cli::try_parse_from(["credman", "admin", "--directory", "synthetic", "--seed-fd", "3",
            "--identity-fd", "4", "backup", "--secret-fd", "5", "--output-fd", "6", "--passphrase"]).is_ok());
        assert!(Cli::try_parse_from(["credman", "admin", "--directory", "synthetic", "--seed-fd", "3",
            "--identity-fd", "4", "restore", "--secret-fd", "5", "--backup-fd", "6"]).is_ok());
        assert!(Cli::try_parse_from(["credman", "admin", "--directory", "synthetic", "--seed-fd", "3",
            "--identity-fd", "4", "recover"]).is_ok());
        assert!(Cli::try_parse_from(["credman"]).is_err());
        assert!(Cli::try_parse_from(["credman", "unsupported"]).is_err());
        for option in ["--unknown", "--seed"] {
            assert!(Cli::try_parse_from(["credman", option, "synthetic", "serve", "--directory", "synthetic",
                "--seed-fd", "3", "--config-fd", "4", "--admin-fd", "5"]).is_err());
        }
        assert!(Cli::try_parse_from(["credman", "admin", "--directory", "synthetic", "--seed-fd", "3",
            "--identity-fd", "4", "unsupported"]).is_err());
    }

    #[test]
    fn failures_print_the_error_kind_and_a_distinct_exit_code() {
        use std::collections::BTreeSet;
        let samples = [
            (Error::Denied, 10, "access denied"),
            (Error::Invalid, 11, "invalid request"),
            (Error::Conflict, 12, "revision conflict"),
            (Error::ReplayConflict, 13, "request identifier reused with different input"),
            (Error::ClockRecoveryRequired, 14, "trusted clock recovery required"),
            (Error::Capacity, 15, "capacity reached"),
            (Error::InteractionRequired, 16, "private delivery unavailable"),
            (Error::GenerationUnavailable, 17, "private credential generation unavailable"),
            (Error::NotPublished, 18, "storage publication did not occur"),
            (Error::RecoveryRequired, 19, "validated storage recovery required"),
            (Error::InvalidStorage, 20, "invalid encrypted agent vault"),
            (Error::InUse, 21, "agent vault is in use"),
        ];
        let mut codes = BTreeSet::new();
        for (error, code, text) in samples {
            let failure = fail("serve", error);
            assert_eq!(failure.report(), format!("credman serve: {text}"));
            assert_eq!(failure.code(), code);
            assert!(codes.insert(code));
            assert!(!failure.report().contains('/') && !failure.report().contains("seed"));
        }
        assert_eq!(fail("mcp", Error::Invalid).report(), "credman mcp: invalid request");
        assert_eq!(fail("admin", Error::RecoveryRequired).report(), "credman admin: validated storage recovery required");
        assert_eq!(fail("serve", Error::RecoveryRequired).report(), "credman serve: validated storage recovery required");
        assert_eq!(codes.len(), samples.len());
    }
}
