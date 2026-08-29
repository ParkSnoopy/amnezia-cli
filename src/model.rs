use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    OpenVpn,
    WireGuard,
    AmneziaWg,
    Xray,
    Shadowsocks,
    Ikev2,
    Amnezia,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::OpenVpn => "OpenVPN",
            Self::WireGuard => "WireGuard",
            Self::AmneziaWg => "AmneziaWG",
            Self::Xray => "XRay",
            Self::Shadowsocks => "Shadowsocks",
            Self::Ikev2 => "IKEv2",
            Self::Amnezia => "Amnezia",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub source: String,
    pub enabled: bool,
    pub server_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
    pub default_profile: Option<String>,
    pub installed_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RouteMode {
    All,
    OnlyListed,
    ExceptListed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub primary_dns: String,
    pub secondary_dns: String,
    pub amnezia_dns: bool,
    pub kill_switch: bool,
    pub strict_kill_switch: bool,
    pub auto_connect: bool,
    pub auto_start: bool,
    pub start_minimized: bool,
    pub logging: bool,
    pub notifications: bool,
    pub screenshots: bool,
    pub route_mode: RouteMode,
    pub split_routes: Vec<String>,
    pub split_apps: Vec<String>,
    pub kill_switch_exceptions: Vec<String>,
    pub language: String,
    pub gateway_endpoint: Option<String>,
    pub subscription_key: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            primary_dns: "1.1.1.1".into(),
            secondary_dns: "1.0.0.1".into(),
            amnezia_dns: false,
            kill_switch: false,
            strict_kill_switch: false,
            auto_connect: false,
            auto_start: false,
            start_minimized: false,
            logging: true,
            notifications: true,
            screenshots: false,
            route_mode: RouteMode::All,
            split_routes: Vec::new(),
            split_apps: Vec::new(),
            kill_switch_exceptions: Vec::new(),
            language: "en".into(),
            gateway_endpoint: None,
            subscription_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub profile_id: String,
    pub pid: Option<u32>,
    pub interface: Option<String>,
    pub started_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub profiles: BTreeMap<String, Profile>,
    pub servers: BTreeMap<String, Server>,
    pub default_profile: Option<String>,
    pub default_server: Option<String>,
    pub settings: Settings,
    pub connection: Option<Connection>,
}
