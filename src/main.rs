mod backup;
mod cli;
mod clipboard;
mod crypto;
mod model;
mod tui;
mod usb;
mod validation;
mod vault;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
