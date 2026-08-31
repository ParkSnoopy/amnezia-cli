use amn::{
    cli::Cli,
    core::Store,
};
use anyhow::{
    Context,
    Result,
    bail,
};
use clap::Parser;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", amn::sanitize_terminal(&format!("{error:#}")));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = Cli::parse();
    let store = if arguments.dry_run {
        Store::discover_read_only(arguments.data_dir)?
    } else {
        Store::discover(arguments.data_dir)?
    };
    let mut state = if arguments.dry_run {
        store.load_without_migration()?
    } else {
        store.load()?
    };

    if arguments.tui {
        if arguments.command.is_some() {
            bail!("--tui cannot be combined with a CLI command");
        }
        if arguments.dry_run {
            bail!("--dry-run applies only to CLI commands; use the TUI preview action");
        }
        return amn::tui::run(&store, &mut state);
    }

    let command = arguments
        .command
        .context("no command specified; use --help")?;
    amn::cli::run(&store, &mut state, command, arguments.dry_run)
}
