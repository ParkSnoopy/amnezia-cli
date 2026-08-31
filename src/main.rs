use amn::{
    cli::Cli,
    core::{Command, Store},
};
use anyhow::{
    Context,
    Result,
    bail,
};
use clap::{
    CommandFactory,
    Parser,
    error::ErrorKind,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", amn::sanitize_terminal(&format!("{error:#}")));
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = parse_arguments();
    if arguments.tui && arguments.command.is_some() {
        bail!("--tui cannot be combined with a CLI command");
    }
    if matches!(arguments.command.as_ref(), Some(Command::Install)) {
        if arguments.dry_run {
            bail!("--dry-run is not supported for install");
        }
        println!("{}", amn::core::install::install()?);
        return Ok(());
    }
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

fn parse_arguments() -> Cli {
    match Cli::try_parse() {
        Ok(arguments) => arguments,
        Err(error) if error.kind() == ErrorKind::InvalidSubcommand => {
            let exit_code = error.exit_code();
            error.print().expect("print invalid command error");
            println!();
            Cli::command().print_long_help().expect("print command help");
            println!();
            std::process::exit(exit_code);
        }
        Err(error) => error.exit(),
    }
}
