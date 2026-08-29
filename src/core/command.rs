use std::path::PathBuf;

use anyhow::{
    Context,
    Result,
};
use clap::{
    Args,
    Parser,
    Subcommand,
    ValueEnum,
};
use strum::EnumIter;

#[derive(Debug, Subcommand)]
pub enum Command {
    Status,
    Connect {
        profile: Option<String>,
    },
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
    Show {
        id: String,
    },
    Import {
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    Export {
        id: String,
        destination: PathBuf,
    },
    Remove {
        id: String,
    },
    Rename {
        id: String,
        name: String,
    },
    Enable {
        id: String,
    },
    Disable {
        id: String,
    },
    Default {
        id: String,
    },
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
    Show {
        id: String,
    },
    Remove {
        id: String,
    },
    Rename {
        id: String,
        name: String,
    },
    Default {
        id: String,
    },
    Test {
        id: String,
    },
    Scan {
        id: String,
    },
    Reboot {
        id: String,
        #[arg(long)]
        yes: bool,
    },
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

#[derive(Clone, Copy)]
pub struct ActionInfo {
    pub category: &'static str,
    pub label: &'static str,
    pub command: &'static str,
    pub prompt: &'static str,
}

pub trait TuiAction {
    fn info(self) -> ActionInfo;
    fn parse(self, input: &str) -> Result<Command>;
}

#[derive(Clone, Copy, Default, EnumIter, Eq, PartialEq)]
pub enum FeatureAction {
    #[default]
    Status,
    Connect,
    Disconnect,
    ProfileList,
    ProfileShow,
    ProfileImport,
    ProfileExport,
    ProfileRemove,
    ProfileRename,
    ProfileEnable,
    ProfileDisable,
    ProfileDefault,
    ServerList,
    ServerAdd,
    ServerShow,
    ServerRemove,
    ServerRename,
    ServerDefault,
    ServerTest,
    ServerScan,
    ServerReboot,
    SettingsShow,
    SettingsSet,
    SettingsReset,
    SplitList,
    SplitAdd,
    SplitRemove,
    SplitClear,
    SplitMode,
    BackupCreate,
    BackupRestore,
    LogsShow,
    LogsExport,
    LogsClear,
    Doctor,
}

impl TuiAction for FeatureAction {
    fn info(self) -> ActionInfo {
        match self {
            Self::Status => ActionInfo::new("Connection", "Status", "status", ""),
            Self::Connect => ActionInfo::new("Connection", "Connect", "connect", "[PROFILE_ID]"),
            Self::Disconnect => ActionInfo::new("Connection", "Disconnect", "disconnect", ""),
            Self::ProfileList => ActionInfo::new("Profiles", "List", "profile list", ""),
            Self::ProfileShow => ActionInfo::new("Profiles", "Show", "profile show", "<ID>"),
            Self::ProfileImport => {
                ActionInfo::new(
                    "Profiles",
                    "Import",
                    "profile import",
                    "<PATH> [--name NAME]",
                )
            }
            Self::ProfileExport => {
                ActionInfo::new("Profiles", "Export", "profile export", "<ID> <DESTINATION>")
            }
            Self::ProfileRemove => ActionInfo::new("Profiles", "Remove", "profile remove", "<ID>"),
            Self::ProfileRename => {
                ActionInfo::new("Profiles", "Rename", "profile rename", "<ID> <NAME>")
            }
            Self::ProfileEnable => ActionInfo::new("Profiles", "Enable", "profile enable", "<ID>"),
            Self::ProfileDisable => {
                ActionInfo::new("Profiles", "Disable", "profile disable", "<ID>")
            }
            Self::ProfileDefault => {
                ActionInfo::new("Profiles", "Set default", "profile default", "<ID>")
            }
            Self::ServerList => ActionInfo::new("Servers", "List", "server list", ""),
            Self::ServerAdd => {
                ActionInfo::new(
                    "Servers",
                    "Add",
                    "server add",
                    "<HOST> [--name NAME] [--user USER] [--port PORT] [--identity PATH]",
                )
            }
            Self::ServerShow => ActionInfo::new("Servers", "Show", "server show", "<ID>"),
            Self::ServerRemove => ActionInfo::new("Servers", "Remove", "server remove", "<ID>"),
            Self::ServerRename => {
                ActionInfo::new("Servers", "Rename", "server rename", "<ID> <NAME>")
            }
            Self::ServerDefault => {
                ActionInfo::new("Servers", "Set default", "server default", "<ID>")
            }
            Self::ServerTest => ActionInfo::new("Servers", "Test", "server test", "<ID>"),
            Self::ServerScan => ActionInfo::new("Servers", "Scan", "server scan", "<ID>"),
            Self::ServerReboot => {
                ActionInfo::new("Servers", "Reboot", "server reboot", "<ID> --yes")
            }
            Self::SettingsShow => ActionInfo::new("Settings", "Show", "settings show", ""),
            Self::SettingsSet => {
                ActionInfo::new("Settings", "Set", "settings set", "<KEY> <VALUE>")
            }
            Self::SettingsReset => ActionInfo::new("Settings", "Reset", "settings reset", ""),
            Self::SplitList => ActionInfo::new("Split tunnel", "List", "split-tunnel list", ""),
            Self::SplitAdd => {
                ActionInfo::new("Split tunnel", "Add", "split-tunnel add", "route <CIDR>")
            }
            Self::SplitRemove => {
                ActionInfo::new(
                    "Split tunnel",
                    "Remove",
                    "split-tunnel remove",
                    "route <CIDR>",
                )
            }
            Self::SplitClear => {
                ActionInfo::new("Split tunnel", "Clear", "split-tunnel clear", "route")
            }
            Self::SplitMode => {
                ActionInfo::new(
                    "Split tunnel",
                    "Mode",
                    "split-tunnel mode",
                    "<all|only-listed|except-listed>",
                )
            }
            Self::BackupCreate => {
                ActionInfo::new("Backup", "Create", "backup create", "<DESTINATION>")
            }
            Self::BackupRestore => {
                ActionInfo::new("Backup", "Restore", "backup restore", "<SOURCE>")
            }
            Self::LogsShow => ActionInfo::new("Logs", "Show", "logs show", ""),
            Self::LogsExport => ActionInfo::new("Logs", "Export", "logs export", "<DESTINATION>"),
            Self::LogsClear => ActionInfo::new("Logs", "Clear", "logs clear", ""),
            Self::Doctor => ActionInfo::new("Diagnostics", "Doctor", "doctor", ""),
        }
    }

    fn parse(self, input: &str) -> Result<Command> {
        let mut arguments = vec!["amn-action".to_owned()];
        arguments.extend(self.info().command.split_whitespace().map(str::to_owned));
        arguments.extend(shlex::split(input).context("input contains an unterminated quote")?);
        ActionParser::try_parse_from(arguments)?
            .command
            .context("selected action did not produce a command")
    }
}

impl ActionInfo {
    const fn new(
        category: &'static str,
        label: &'static str,
        command: &'static str,
        prompt: &'static str,
    ) -> Self {
        Self {
            category,
            label,
            command,
            prompt,
        }
    }
}

#[derive(Parser)]
#[command(name = "amn-action")]
struct ActionParser {
    #[command(subcommand)]
    command: Option<Command>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::CommandFactory;
    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn tui_actions_cover_every_cli_leaf_command() {
        let mut commands = BTreeSet::new();
        collect_leaf_commands(&ActionParser::command(), "", &mut commands);
        let actions = FeatureAction::iter()
            .map(|action| action.info().command.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(actions, commands);
    }

    fn collect_leaf_commands(command: &clap::Command, prefix: &str, output: &mut BTreeSet<String>) {
        for subcommand in command.get_subcommands() {
            let path = if prefix.is_empty() {
                subcommand.get_name().to_owned()
            } else {
                format!("{prefix} {}", subcommand.get_name())
            };
            if subcommand.has_subcommands() {
                collect_leaf_commands(subcommand, &path, output);
            } else {
                output.insert(path);
            }
        }
    }
}
