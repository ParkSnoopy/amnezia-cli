use std::collections::BTreeMap;

use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    OpenVpn,
    WireGuard,
    AmneziaWg,
    Xray,
    Shadowsocks,
    Ikev2,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_file: Option<String>,
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
    pub logging: bool,
    pub route_mode: RouteMode,
    pub split_routes: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            logging: true,
            route_mode: RouteMode::All,
            split_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ikev2RouteIdentity {
    pub endpoint: String,
    pub gateway: String,
    pub uplink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub profile_id: String,
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_start_ticks: Option<u64>,
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ikev2_route: Option<Ikev2RouteIdentity>,
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
