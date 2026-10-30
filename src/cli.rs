use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "credman", about = "Private native credential broker for supervised agents")]
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

pub(crate) fn run() -> Result<()> {
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
                .map_err(|_| anyhow::anyhow!("administration refused"))
        }
        Commands::Serve { directory, seed_fd, config_fd, admin_fd, create, bridge_socket } => {
            let options = crate::agent_broker::RunOptions { directory, seed_fd, config_fd, admin_fd, create, bridge_socket };
            crate::agent_broker::run(options).map_err(|_| anyhow::anyhow!("broker refused"))
        }
        Commands::Mcp { session_file } => crate::agent_mcp::run(&session_file)
            .map_err(|_| anyhow::anyhow!("MCP refused")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_native_commands_and_descriptor_options_are_accepted() {
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
        for command in ["agent-run", "agent-admin", "init", "status", "backup", "restore", "add", "get",
            "list", "edit", "rm", "tui", "export", "import", "usb", "clipboard-clear"] {
            assert!(Cli::try_parse_from(["credman", command]).is_err(), "accepted {command}");
        }
        for option in ["--vault", "--seed"] {
            assert!(Cli::try_parse_from(["credman", option, "synthetic", "serve", "--directory", "synthetic",
                "--seed-fd", "3", "--config-fd", "4", "--admin-fd", "5"]).is_err());
        }
        for operation in ["import-v1", "import-receipt"] {
            assert!(Cli::try_parse_from(["credman", "admin", "--directory", "synthetic", "--seed-fd", "3",
                "--identity-fd", "4", operation]).is_err());
        }
    }
}
