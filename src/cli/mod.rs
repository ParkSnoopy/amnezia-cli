use crate::core::{Command, State, Store};
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "amn", version, about = "AmneziaVPN CLI", arg_required_else_help = true)]
pub struct Cli {
    #[arg(long, help = "Launch AmneziaVPN TUI")]
    pub tui: bool,
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    #[arg(long, global = true, help = "Print external command instead of executing it")]
    pub dry_run: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

pub fn run(store: &Store, state: &mut State, command: Command, dry_run: bool) -> Result<()> {
    let output = crate::core::execute(store, state, command, dry_run)?;
    print!("{output}");
    Ok(())
}
