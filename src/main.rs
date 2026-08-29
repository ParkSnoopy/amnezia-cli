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
    let store = Store::discover(arguments.data_dir)?;
    let mut state = store.load()?;
    let had_connection = state.connection.is_some();
    amn::core::runner::refresh_connection(&mut state);
    if had_connection && state.connection.is_none() {
        store.save(&state)?;
    }

    if arguments.tui {
        if arguments.command.is_some() {
            bail!("--tui cannot be combined with a CLI command");
        }
        return amn::tui::run(&store, &mut state);
    }

    let command = arguments
        .command
        .context("no command specified; use --help")?;
    amn::cli::run(&store, &mut state, command, arguments.dry_run)
}
