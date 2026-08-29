use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::net::{IpAddr, ToSocketAddrs};

pub struct RawConfiguration {
    document: Value,
    endpoint_host: String,
    endpoint_port: u16,
    outbound_index: usize,
}

impl RawConfiguration {
    pub fn parse(text: &str) -> Result<Self> {
        let mut document: Value = serde_json::from_str(text).context("raw XRay profile is not valid JSON")?;
        let root = document.as_object_mut().context("raw XRay profile must be a JSON object")?;
        let outbounds = root.get_mut("outbounds").and_then(Value::as_array_mut).context("raw XRay profile has no outbounds array")?;
        let (outbound_index, outbound) = outbounds.iter_mut().enumerate().find(|(_, outbound)| {
            outbound.get("protocol").and_then(Value::as_str).is_some_and(|protocol| protocol.eq_ignore_ascii_case("vless"))
                && outbound.pointer("/streamSettings/network").and_then(Value::as_str).is_some_and(|network| network.eq_ignore_ascii_case("raw"))
                && outbound.pointer("/streamSettings/security").and_then(Value::as_str).is_some_and(|security| security.eq_ignore_ascii_case("reality"))
        }).context("raw XRay profile requires a VLESS Reality outbound using the raw transport")?;
        let reality = outbound.pointer("/streamSettings/realitySettings").and_then(Value::as_object)
            .context("raw XRay VLESS outbound has no Reality settings")?;
        if reality.get("serverName").and_then(Value::as_str).is_none_or(str::is_empty) {
            bail!("raw XRay Reality settings require serverName");
        }
        if reality.get("publicKey").or_else(|| reality.get("password")).and_then(Value::as_str).is_none_or(str::is_empty) {
            bail!("raw XRay Reality settings require a public key");
        }
        let server = outbound.pointer_mut("/settings/vnext/0").and_then(Value::as_object_mut)
            .context("raw XRay VLESS outbound has no primary server")?;
        let endpoint_host = server.get("address").and_then(Value::as_str).filter(|value| !value.is_empty())
            .context("raw XRay VLESS server has no address")?.to_owned();
        let endpoint_port = server.get("port").and_then(Value::as_u64).and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0).context("raw XRay VLESS server has an invalid port")?;

        root.insert("inbounds".into(), json!([{
            "tag": "amn-socks",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true }
        }]));
        root.insert("log".into(), json!({ "loglevel": "warning" }));
        for unsupported in ["api", "metrics", "reverse", "stats", "observatory", "burstObservatory"] {
            root.remove(unsupported);
        }

        Ok(Self { document, endpoint_host, endpoint_port, outbound_index })
    }

    pub fn endpoint_ipv4(&self) -> Result<std::net::Ipv4Addr> {
        (self.endpoint_host.as_str(), self.endpoint_port)
            .to_socket_addrs()
            .with_context(|| format!("resolve XRay endpoint {}", self.endpoint_host))?
            .find_map(|address| match address.ip() {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
            .context("raw XRay endpoint has no IPv4 address")
    }

    pub fn render_for_endpoint(mut self, endpoint: std::net::Ipv4Addr) -> Result<String> {
        let outbounds = self.document.get_mut("outbounds").and_then(Value::as_array_mut).context("validated XRay outbounds disappeared")?;
        let server = outbounds.get_mut(self.outbound_index).and_then(|outbound| outbound.pointer_mut("/settings/vnext/0"))
            .and_then(Value::as_object_mut).context("validated XRay server disappeared")?;
        server.insert("address".into(), Value::String(endpoint.to_string()));
        serde_json::to_string(&self.document).context("serialize normalized XRay configuration")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_raw_vless_reality_and_replaces_inbounds() {
        let profile = r#"{
            "inbounds":[{"listen":"0.0.0.0","port":1,"protocol":"dokodemo-door"}],
            "outbounds":[{
                "protocol":"vless",
                "settings":{"vnext":[{"address":"vpn.example","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},
                "streamSettings":{"network":"raw","security":"reality","realitySettings":{"serverName":"vpn.example","publicKey":"key"}}
            }]
        }"#;
        let rendered = RawConfiguration::parse(profile).unwrap().render_for_endpoint("192.0.2.1".parse().unwrap()).unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value.pointer("/inbounds/0/listen").and_then(Value::as_str), Some("127.0.0.1"));
        assert_eq!(value.pointer("/outbounds/0/settings/vnext/0/address").and_then(Value::as_str), Some("192.0.2.1"));
        assert!(value.get("api").is_none());
    }

    #[test]
    fn rejects_non_raw_or_non_reality_xray_profiles() {
        let profile = r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[]},"streamSettings":{"network":"tcp","security":"tls"}}]}"#;
        assert!(RawConfiguration::parse(profile).is_err());
    }
}
