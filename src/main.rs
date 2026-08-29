use amn::cli::Cli;
use clap::Parser;

fn main() {
    if let Err(error) = amn::run(Cli::parse()) {
        eprintln!("error: {}", amn::sanitize_terminal(&format!("{error:#}")));
        std::process::exit(1);
    }
}
