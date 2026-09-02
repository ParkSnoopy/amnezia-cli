use std::collections::BTreeMap;

use serde::{
    Deserialize,
    Serialize,
};

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    OpenVpn,
    WireGuard,
    AmneziaWg,
    Xray,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::OpenVpn => "OpenVPN",
            Self::WireGuard => "WireGuard",
            Self::AmneziaWg => "AmneziaWG",
            Self::Xray => "XRay",
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
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            logging: true,
            route_mode: RouteMode::All,
            split_routes: Vec::new(),
            dns_servers: default_dns_servers(),
        }
    }
}

fn default_dns_servers() -> Vec<String> {
    vec!["1.1.1.1".into(), "1.0.0.1".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayRouteIdentity {
    pub endpoint: String,
    pub gateway: String,
    pub uplink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub recovery_required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disconnecting: bool,
    pub pid: Option<u32>,
    #[serde(default)]
    pub process_start_ticks: Option<u64>,
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_directory: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub quick_root_owned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray_route: Option<XrayRouteIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xray_owned_routes: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub profiles: BTreeMap<String, Profile>,
    pub default_profile: Option<String>,
    pub settings: Settings,
    pub connection: Option<Connection>,
}
