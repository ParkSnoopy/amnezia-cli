use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use url::Url;

const SUPPORTED_OUTBOUNDS: &[&str] = &["vless", "vmess", "trojan"];
const SUPPORTED_NETWORKS: &[&str] = &[
    "tcp", "raw", "http", "h2", "ws", "kcp", "quic", "grpc", "xhttp",
];
const SUPPORTED_LINK_NETWORKS: &[&str] = &["tcp", "http", "ws", "kcp", "quic", "grpc"];

pub(crate) struct Adapter;

impl crate::core::transaction::sealed::Sealed for Adapter {}

impl crate::core::transaction::ProtocolAdapter for Adapter {
    const PROTOCOL: crate::core::model::Protocol = crate::core::model::Protocol::Xray;

    fn prepare(
        request: crate::core::transaction::PrepareRequest<'_>,
    ) -> anyhow::Result<crate::core::transaction::ProtocolRecipe> {
        Ok(crate::core::transaction::ProtocolRecipe::Xray(
            Configuration::parse(request.source)?,
        ))
    }
}

pub struct Configuration {
    document: Value,
    endpoint_host: String,
    endpoint_port: u16,
}

impl Configuration {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let document = if text.starts_with("vless://") {
            link_document(text, "vless")?
        } else if text.starts_with("trojan://") {
            link_document(text, "trojan")?
        } else if text.starts_with("vmess://") {
            vmess_document(text)?
        } else {
            serde_json::from_str(text).context("XRay profile is not valid JSON or a supported share link")?
        };
        Self::from_document(document)
    }

    fn from_document(mut document: Value) -> Result<Self> {
        let root = document
            .as_object_mut()
            .context("XRay profile must be a JSON object")?;
        let outbounds = root
            .get("outbounds")
            .and_then(Value::as_array)
            .context("XRay profile has no outbounds array")?;
        let mut outbound = outbounds
            .iter()
            .find(|outbound| {
                outbound
                    .get("protocol")
                    .and_then(Value::as_str)
                    .is_some_and(|protocol| SUPPORTED_OUTBOUNDS.contains(&protocol))
            })
            .cloned()
            .context("XRay profile has no supported VLESS, VMess, or Trojan outbound")?;
        let protocol = outbound
            .get("protocol")
            .and_then(Value::as_str)
            .context("validated XRay outbound has no protocol")?;
        let server_pointer = if protocol == "trojan" {
            "/settings/servers"
        } else {
            "/settings/vnext"
        };
        let servers = outbound
            .pointer(server_pointer)
            .and_then(Value::as_array)
            .context("XRay outbound has no servers")?;
        if servers.len() != 1 {
            bail!("XRay profiles must contain exactly one remote server");
        }
        let server = servers[0]
            .as_object()
            .context("XRay primary server is not an object")?;
        let endpoint_host = server
            .get("address")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("XRay server has no address")?
            .to_owned();
        let endpoint_port =
            value_port(server.get("port")).context("XRay server has an invalid port")?;
        validate_server_credentials(protocol, server)?;

        if let Some(stream) = outbound.get("streamSettings") {
            let stream = stream
                .as_object()
                .context("XRay stream settings must be an object")?;
            if let Some(network) = stream.get("network") {
                let network = network
                    .as_str()
                    .context("XRay stream network must be a string")?;
                if !network.is_empty() && !SUPPORTED_NETWORKS.contains(&network) {
                    bail!("XRay transport is not supported by the pinned upstream client: {network}");
                }
            }
            if let Some(security) = stream.get("security") {
                let security = security
                    .as_str()
                    .context("XRay stream security must be a string")?;
                if !["none", "tls", "xtls", "reality"].contains(&security) {
                    bail!("XRay stream security is not supported: {security}");
                }
                let settings_key = match security {
                    "tls" => Some("tlsSettings"),
                    "xtls" => Some("xtlsSettings"),
                    "reality" => Some("realitySettings"),
                    _ => None,
                };
                if let Some(settings_key) = settings_key {
                    let settings = stream.get(settings_key);
                    if security == "reality" && settings.is_none() {
                        bail!("XRay Reality security requires realitySettings");
                    }
                    if let Some(settings) = settings {
                        let settings = settings.as_object().with_context(|| {
                            format!("XRay {settings_key} must be an object")
                        })?;
                        reject_xray_security_file_inputs(settings)?;
                        if security == "reality"
                            && !settings
                                .get("publicKey")
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                        {
                            bail!("XRay Reality security requires a public key");
                        }
                        if settings
                            .get("allowInsecure")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            bail!("XRay insecure certificate verification is not allowed");
                        }
                    }
                }
            }
        }
        outbound
            .as_object_mut()
            .context("XRay outbound is not an object")?
            .insert("tag".into(), Value::String("amn-proxy".into()));

        root.insert(
            "inbounds".into(),
            json!([{
                "tag": "amn-socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": { "auth": "noauth", "udp": true }
            }]),
        );
        root.insert("outbounds".into(), Value::Array(vec![outbound]));
        root.insert(
            "routing".into(),
            json!({
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "inboundTag": ["amn-socks"],
                    "outboundTag": "amn-proxy"
                }]
            }),
        );
        root.insert("log".into(), json!({ "loglevel": "warning" }));
        for unsupported in [
            "api",
            "metrics",
            "reverse",
            "stats",
            "observatory",
            "burstObservatory",
        ] {
            root.remove(unsupported);
        }

        Ok(Self {
            document,
            endpoint_host,
            endpoint_port,
        })
    }

    pub fn endpoint_ipv4(&self) -> Result<Ipv4Addr> {
        (self.endpoint_host.as_str(), self.endpoint_port)
            .to_socket_addrs()
            .with_context(|| format!("resolve XRay endpoint {}", self.endpoint_host))?
            .find_map(|address| match address.ip() {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
            .context("XRay endpoint has no IPv4 address")
    }

    pub fn endpoint_port(&self) -> u16 {
        self.endpoint_port
    }

    pub fn render(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.document).context("serialize normalized XRay configuration")
    }

    pub fn render_for_endpoint(&self, endpoint: Ipv4Addr) -> Result<String> {
        let mut document = self.document.clone();
        let outbound = document
            .pointer_mut("/outbounds/0")
            .context("normalized XRay outbound is missing")?;
        let address = match outbound.get("protocol").and_then(Value::as_str) {
            Some("vless" | "vmess") => outbound.pointer_mut("/settings/vnext/0/address"),
            Some("trojan") => outbound.pointer_mut("/settings/servers/0/address"),
            _ => None,
        }
        .context("normalized XRay endpoint address is missing")?;
        *address = Value::String(endpoint.to_string());

        let security = outbound
            .pointer("/streamSettings/security")
            .and_then(Value::as_str)
            .unwrap_or("none");
        let settings_key = match security {
            "tls" => Some("tlsSettings"),
            "xtls" => Some("xtlsSettings"),
            "reality" => Some("realitySettings"),
            _ => None,
        };
        if let Some(settings_key) = settings_key {
            let stream = outbound
                .get_mut("streamSettings")
                .and_then(Value::as_object_mut)
                .context("normalized XRay stream settings are missing")?;
            let secure = stream
                .entry(settings_key)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .context("normalized XRay security settings are not an object")?;
            secure
                .entry("serverName")
                .or_insert_with(|| Value::String(self.endpoint_host.clone()));
        }
        serde_json::to_string_pretty(&document)
            .context("serialize endpoint-pinned XRay configuration")
    }

    pub fn requires_tcp_endpoint(&self) -> bool {
        !matches!(
            self.document
                .pointer("/outbounds/0/streamSettings/network")
                .and_then(Value::as_str),
            Some("kcp" | "quic")
        )
    }
}

fn validate_server_credentials(protocol: &str, server: &Map<String, Value>) -> Result<()> {
    if protocol == "trojan" {
        if server
            .get("password")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("Trojan outbound has no password");
        }
        return Ok(());
    }
    let users = server
        .get("users")
        .and_then(Value::as_array)
        .filter(|users| !users.is_empty())
        .context("XRay outbound server has no users")?;
    for user in users {
        if user
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("XRay outbound user has no ID");
        }
    }
    Ok(())
}

fn link_document(text: &str, protocol: &str) -> Result<Value> {
    let url = Url::parse(text).context("XRay share link is invalid")?;
    let host = url.host_str().filter(|value| !value.is_empty()).context("XRay share link has no host")?;
    let port = url.port().context("XRay share link has no port")?;
    let credential = percent_decode(url.username())?;
    if credential.is_empty() {
        bail!("XRay share link has no credential");
    }
    let query = query_map(&url);
    let stream = stream_settings(&query)?;
    let settings = if protocol == "trojan" {
        json!({"servers": [{"address": host, "port": port, "password": credential}]})
    } else {
        let encryption = query_string(&query, "encryption").unwrap_or("none");
        let mut user = json!({"id": credential, "encryption": encryption});
        let security = query_string(&query, "security").unwrap_or("none");
        if matches!(security, "xtls" | "reality")
            && let Some(flow) = query_string(&query, "flow").filter(|value| !value.is_empty())
        {
            user["flow"] = Value::String(flow.to_owned());
        }
        json!({"vnext": [{"address": host, "port": port, "users": [user]}]})
    };
    Ok(json!({
        "outbounds": [{"tag": "amn-proxy", "protocol": protocol, "settings": settings, "streamSettings": stream}]
    }))
}

fn vmess_document(text: &str) -> Result<Value> {
    if text.contains('@') {
        bail!("this VMess URL form is not importable by the pinned upstream client");
    }

    let encoded = text.strip_prefix("vmess://").context("VMess share link is invalid")?;
    let decoded = crate::core::encoding::decode_base64(encoded, "VMess share link is not valid base64")?;
    let legacy: Value = serde_json::from_slice(&decoded).context("VMess share link payload is not valid JSON")?;
    let host = legacy_string(&legacy, "add")?;
    let port = value_port(legacy.get("port")).context("VMess share link has an invalid port")?;
    let id = legacy_string(&legacy, "id")?;
    let alter_id = legacy.get("aid").and_then(value_u64).unwrap_or(0);
    let security = match legacy
        .get("scy")
        .and_then(Value::as_str)
        .unwrap_or("aes-128-gcm")
    {
        value @ ("auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero") => value,
        _ => "aes-128-gcm",
    };
    let mut query = Map::new();
    for (source, destination) in [
        ("net", "type"),
        ("type", "headerType"),
        ("host", "host"),
        ("path", "path"),
        ("tls", "security"),
        ("sni", "sni"),
        ("alpn", "alpn"),
    ] {
        if let Some(value) = legacy.get(source).and_then(Value::as_str).filter(|value| !value.is_empty()) {
            query.insert(destination.into(), Value::String(value.into()));
        }
    }
    if query_string(&query, "type") == Some("h2") {
        query.insert("type".into(), Value::String("http".into()));
    }
    if !matches!(
        query_string(&query, "type"),
        None | Some("tcp" | "http" | "ws" | "kcp" | "quic" | "grpc")
    ) {
        query.insert("type".into(), Value::String("tcp".into()));
    }
    if query_string(&query, "security") != Some("tls") {
        query.insert("security".into(), Value::String("none".into()));
    } else if query_string(&query, "sni").is_none()
        && let Some(host) = query_string(&query, "host").map(str::to_owned)
    {
        query.insert("sni".into(), Value::String(host));
    }
    if query_string(&query, "type") == Some("quic") {
        if let Some(value) = query.remove("host") {
            query.insert("quicSecurity".into(), value);
        }
        if let Some(value) = query.remove("path") {
            query.insert("key".into(), value);
        }
    }
    let stream = stream_settings(&query)?;
    Ok(json!({
        "outbounds": [{
            "tag": "amn-proxy",
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": id, "alterId": alter_id, "security": security}]}]},
            "streamSettings": stream
        }]
    }))
}

fn stream_settings(query: &Map<String, Value>) -> Result<Value> {
    let network = query_string(query, "type").unwrap_or("tcp");
    if !SUPPORTED_LINK_NETWORKS.contains(&network) {
        bail!("XRay share-link transport is unsupported: {network}");
    }
    let security = query_string(query, "security").unwrap_or("none");
    let mut stream = json!({"network": network, "security": security});
    let settings_key = match network {
        "tcp" => "tcpSettings",
        "http" => "httpSettings",
        "ws" => "wsSettings",
        "kcp" => "kcpSettings",
        "quic" => "quicSettings",
        "grpc" => "grpcSettings",
        _ => bail!("XRay share-link transport is unsupported: {network}"),
    };
    let mut transport = Map::new();
    if let Some(path) = query_string(query, "path").filter(|value| !value.is_empty()) {
        let key = if network == "grpc" { "serviceName" } else { "path" };
        transport.insert(key.into(), Value::String(path.into()));
    }
    if let Some(host) = query_string(query, "host").filter(|value| !value.is_empty()) {
        if matches!(network, "http" | "h2") {
            transport.insert("host".into(), Value::Array(host.split(',').map(|value| Value::String(value.into())).collect()));
        } else if network == "ws" {
            transport.insert("headers".into(), json!({"Host": host}));
        } else {
            transport.insert("host".into(), Value::String(host.into()));
        }
    }
    if let Some(seed) = query_string(query, "seed").filter(|value| !value.is_empty()) {
        transport.insert("seed".into(), Value::String(seed.into()));
    }
    if let Some(header) = query_string(query, "headerType").filter(|value| *value != "none" && !value.is_empty()) {
        transport.insert("header".into(), json!({"type": header}));
    }
    if network == "quic"
        && let Some(quic_security) = query_string(query, "quicSecurity")
            .filter(|value| !value.is_empty())
    {
        transport.insert("security".into(), Value::String(quic_security.into()));
        if quic_security != "none"
            && let Some(key) = query_string(query, "key").filter(|value| !value.is_empty())
        {
            transport.insert("key".into(), Value::String(key.into()));
        }
    }
    if network == "grpc"
        && let Some(mode) = query_string(query, "mode").filter(|value| !value.is_empty())
    {
        transport.insert("multiMode".into(), Value::Bool(mode == "multi"));
    }
    if !transport.is_empty() {
        stream[settings_key] = Value::Object(transport);
    }

    if security != "none" {
        let key = match security {
            "tls" => "tlsSettings",
            "xtls" => "xtlsSettings",
            "reality" => "realitySettings",
            value => bail!("XRay share-link security is unsupported: {value}"),
        };
        let mut secure = Map::new();
        if let Some(value) = query_string(query, "sni").filter(|value| !value.is_empty()) {
            secure.insert("serverName".into(), Value::String(value.into()));
        }
        if let Some(value) = query_string(query, "alpn").filter(|value| !value.is_empty()) {
            let values = value
                .split(',')
                .filter(|value| *value != "h2")
                .map(|value| Value::String(value.into()))
                .collect::<Vec<_>>();
            if !values.is_empty() {
                secure.insert("alpn".into(), Value::Array(values));
            }
        }
        for (source, destination) in [
            ("fp", "fingerprint"),
            ("pbk", "publicKey"),
            ("sid", "shortId"),
            ("spiderX", "spiderX"),
        ] {
            if let Some(value) = query_string(query, source).filter(|value| !value.is_empty()) {
                secure.insert(destination.into(), Value::String(value.into()));
            }
        }
        stream[key] = Value::Object(secure);
    }
    Ok(stream)
}

fn query_string<'a>(query: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    query.get(key).and_then(Value::as_str)
}

fn query_map(url: &Url) -> Map<String, Value> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
        .collect()
}

fn percent_decode(value: &str) -> Result<String> {
    let encoded = value.replace('+', "%2B");
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .map(|(value, _)| value.into_owned())
        .context("XRay share link has invalid percent encoding")
}

fn legacy_string<'a>(document: &'a Value, key: &str) -> Result<&'a str> {
    document
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("VMess share link has no {key}"))
}

fn value_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn reject_xray_security_file_inputs(settings: &Map<String, Value>) -> Result<()> {
    fn inspect(key: &str, value: &Value) -> Result<()> {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("file")
            || normalized.contains("path")
            || normalized == "certificates"
            || normalized == "certificate"
            || normalized == "keyfile"
            || normalized == "certificatefile"
        {
            bail!("XRay security settings may not read external files: {key}");
        }
        match value {
            Value::Object(object) => {
                for (child_key, child) in object {
                    inspect(child_key, child)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    inspect(key, child)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for (key, value) in settings {
        inspect(key, value)?;
    }
    Ok(())
}

fn value_port(value: Option<&Value>) -> Option<u16> {
    value
        .and_then(value_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn accepts_general_upstream_xray_json_transports() {
        for (protocol, network, security) in [
            ("vless", "raw", "reality"),
            ("vless", "xhttp", "tls"),
            ("vless", "kcp", "none"),
            ("vmess", "ws", "tls"),
            ("trojan", "grpc", "tls"),
        ] {
            let settings = if protocol == "trojan" {
                json!({"servers": [{"address": "vpn.example", "port": 443, "password": "secret"}]})
            } else {
                json!({"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]})
            };
            let mut stream_settings = json!({"network": network, "security": security});
            if security == "reality" {
                stream_settings["realitySettings"] = json!({
                    "serverName": "vpn.example",
                    "publicKey": "0123456789abcdef"
                });
            }
            let profile = json!({
                "inbounds": [{"listen": "0.0.0.0"}],
                "outbounds": [{
                    "protocol": protocol,
                    "settings": settings,
                    "streamSettings": stream_settings
                }]
            });
            let rendered = Configuration::parse(&profile.to_string())
                .unwrap()
                .render()
                .unwrap();
            let value: Value = serde_json::from_str(&rendered).unwrap();
            assert_eq!(value.pointer("/inbounds/0/listen").and_then(Value::as_str), Some("127.0.0.1"));
        }
    }

    #[test]
    fn accepts_upstream_vless_and_trojan_links() {
        let links = [
            "vless://00000000-0000-0000-0000-000000000000@vpn.example:443?type=tcp&security=tls&sni=vpn.example#VPN",
            "trojan://password@vpn.example:443?type=grpc&security=tls&sni=vpn.example#VPN",
        ];
        for link in links {
            let configuration = Configuration::parse(link).unwrap();
            assert_eq!(configuration.endpoint_port(), 443);
        }
    }

    #[test]
    fn matches_upstream_transport_query_mapping() {
        let quic = Configuration::parse(
            "vless://00000000-0000-0000-0000-000000000000@vpn.example:443?type=quic&security=tls&quicSecurity=aes-128-gcm&key=secret&headerType=srtp",
        )
        .unwrap()
        .render()
        .unwrap();
        let quic: Value = serde_json::from_str(&quic).unwrap();
        assert_eq!(
            quic.pointer("/outbounds/0/streamSettings/quicSettings/security")
                .and_then(Value::as_str),
            Some("aes-128-gcm")
        );
        let grpc = Configuration::parse(
            "trojan://password@vpn.example:443?type=grpc&security=tls&serviceName=vpn&mode=multi",
        )
        .unwrap()
        .render()
        .unwrap();
        let grpc: Value = serde_json::from_str(&grpc).unwrap();
        assert_eq!(
            grpc.pointer("/outbounds/0/streamSettings/grpcSettings/multiMode")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn accepts_legacy_vmess_links() {
        let legacy = json!({
            "v": "2",
            "ps": "VPN",
            "add": "vpn.example",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000000",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "vpn.example",
            "path": "/socket",
            "tls": "tls",
            "sni": "vpn.example"
        });
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(legacy.to_string().as_bytes())
        );
        let configuration = Configuration::parse(&link).unwrap();
        assert_eq!(configuration.endpoint_host, "vpn.example");
        assert_eq!(configuration.endpoint_port(), 443);
        let rendered = configuration
            .render()
            .unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            value
                .pointer("/outbounds/0/streamSettings/network")
                .and_then(Value::as_str),
            Some("ws")
        );
        assert_eq!(
            value
                .pointer("/outbounds/0/settings/vnext/0/users/0/security")
                .and_then(Value::as_str),
            Some("auto")
        );

        let invalid_defaults = json!({
            "add": "vpn.example",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000000",
            "scy": "invalid",
            "net": "invalid",
            "tls": "invalid",
            "alpn": "h2"
        });
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(invalid_defaults.to_string().as_bytes())
        );
        let rendered: Value = serde_json::from_str(
            &Configuration::parse(&link).unwrap().render().unwrap(),
        )
        .unwrap();
        assert_eq!(
            rendered
                .pointer("/outbounds/0/settings/vnext/0/users/0/security")
                .and_then(Value::as_str),
            Some("aes-128-gcm")
        );
        assert_eq!(
            rendered
                .pointer("/outbounds/0/streamSettings/network")
                .and_then(Value::as_str),
            Some("tcp")
        );
        assert_eq!(
            rendered
                .pointer("/outbounds/0/streamSettings/security")
                .and_then(Value::as_str),
            Some("none")
        );
    }

    #[test]
    fn rejects_removed_or_unknown_outbounds() {
        for protocol in ["socks", "freedom"] {
            let profile = json!({"outbounds": [{"protocol": protocol, "settings": {"servers": [{"address": "vpn.example", "port": 443}]}}]});
            assert!(Configuration::parse(&profile.to_string()).is_err());
        }
        let invalid_security = json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"network": "tcp", "security": "definitely-invalid"}
            }]
        });
        assert!(Configuration::parse(&invalid_security.to_string()).is_err());
        let insecure_tls = json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"allowInsecure": true}}
            }]
        });
        assert!(Configuration::parse(&insecure_tls.to_string()).is_err());
        let file_backed_tls = json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/root/cert.pem", "keyFile": "/root/key.pem"}]}}
            }]
        });
        assert!(Configuration::parse(&file_backed_tls.to_string()).is_err());
        let incomplete_reality = json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"security": "reality", "realitySettings": {"serverName": "vpn.example"}}
            }]
        });
        assert!(Configuration::parse(&incomplete_reality.to_string()).is_err());
        let missing_reality_settings = json!({
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"security": "reality"}
            }]
        });
        assert!(Configuration::parse(&missing_reality_settings.to_string()).is_err());
    }

    #[test]
    fn removes_bypass_outbounds_and_preserves_tls_hostname() {
        let profile = json!({
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                    "streamSettings": {"network": "tcp", "security": "tls"}
                },
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {"rules": [{"outboundTag": "direct"}]}
        });
        let configuration = Configuration::parse(&profile.to_string()).unwrap();
        let rendered = configuration
            .render_for_endpoint("192.0.2.1".parse().unwrap())
            .unwrap();
        let rendered: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(rendered["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(
            rendered.pointer("/outbounds/0/settings/vnext/0/address").and_then(Value::as_str),
            Some("192.0.2.1")
        );
        assert_eq!(
            rendered.pointer("/outbounds/0/streamSettings/tlsSettings/serverName").and_then(Value::as_str),
            Some("vpn.example")
        );
        assert_eq!(
            rendered.pointer("/routing/rules/0/outboundTag").and_then(Value::as_str),
            Some("amn-proxy")
        );
    }

    #[test]
    fn rejects_unpinned_share_link_forms_without_panicking() {
        for link in [
            "vless://00000000-0000-0000-0000-000000000000@vpn.example:443?type=WS",
            "vless://00000000-0000-0000-0000-000000000000@vpn.example:443?type=xhttp",
            "vmess://tcp+tls:00000000-0000-0000-0000-000000000000-0@vpn.example:443",
        ] {
            assert!(Configuration::parse(link).is_err());
        }
    }
}
