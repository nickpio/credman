mod agent;
mod agent_bridge;
mod agent_mcp;
mod agent_admin;
mod agent_broker;
mod agent_https;
mod agent_ipc;
mod cli;
mod crypto;

fn main() {
    if let Err(failure) = cli::run() {
        eprintln!("{}", failure.report());
        std::process::exit(failure.code());
    }
}
