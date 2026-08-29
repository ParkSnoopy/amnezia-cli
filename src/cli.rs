use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "amn", version, about = "Qt-free Amnezia VPN CLI and terminal UI", arg_required_else_help = true)]
pub struct Cli {
    #[arg(long, help = "Launch interactive terminal UI")]
    pub tui: bool,
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
    #[arg(long, global = true, help = "Print external command instead of executing it")]
    pub dry_run: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Status,
    Connect { profile: Option<String> },
    Disconnect,
    #[command(subcommand)]
    Profile(ProfileCommand),
    #[command(subcommand)]
    Server(ServerCommand),
    #[command(subcommand)]
    Settings(SettingsCommand),
    #[command(subcommand)]
    SplitTunnel(SplitTunnelCommand),
    #[command(subcommand)]
    Backup(BackupCommand),
    #[command(subcommand)]
    Logs(LogsCommand),
    Doctor,
}

#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    List,
    Show { id: String },
    Import {
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    Export { id: String, destination: PathBuf },
    Remove { id: String },
    Rename { id: String, name: String },
    Enable { id: String },
    Disable { id: String },
    Default { id: String },
}

#[derive(Debug, Args)]
pub struct ServerAdd {
    pub host: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, default_value = "root")]
    pub user: String,
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    #[arg(long)]
    pub identity: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    List,
    Add(ServerAdd),
    Show { id: String },
    Remove { id: String },
    Rename { id: String, name: String },
    Default { id: String },
    Test { id: String },
    Scan { id: String },
    Reboot { id: String, #[arg(long)] yes: bool },
}

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    Show,
    Set { key: String, value: String },
    Reset,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SplitKind {
    Route,
    App,
    KillSwitchException,
}

#[derive(Debug, Subcommand)]
pub enum SplitTunnelCommand {
    List,
    Add { kind: SplitKind, value: String },
    Remove { kind: SplitKind, value: String },
    Clear { kind: SplitKind },
    Mode { mode: SplitMode },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SplitMode {
    All,
    OnlyListed,
    ExceptListed,
}

#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    Create { destination: PathBuf },
    Restore { source: PathBuf },
}

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    Show,
    Export { destination: PathBuf },
    Clear,
}
