use crate::core::xray::RawConfiguration;
use anyhow::{Context, Result, bail};

use serde_json::{Value, json};

pub fn parse(text: &str) -> Result<RawConfiguration> {
    if text.trim_start().starts_with('{') {
        return parse_xray_json(text);
    }
    let uri = text.trim().strip_prefix("ss://").context("Shadowsocks profile must start with ss://")?;
    let authority = uri.split('#').next().unwrap_or_default().split('?').next().unwrap_or_default();
    let decoded;
    let (credentials, endpoint) = if let Some((credentials, endpoint)) = authority.rsplit_once('@') {
        decoded = crate::core::encoding::decode_base64(credentials, "Shadowsocks credentials are not valid base64")?;
        (std::str::from_utf8(&decoded).context("Shadowsocks credentials are not UTF-8")?, endpoint)
    } else {
        decoded = crate::core::encoding::decode_base64(authority, "Shadowsocks URI is not valid base64")?;
        let decoded = std::str::from_utf8(&decoded).context("Shadowsocks URI is not UTF-8")?;
        decoded.rsplit_once('@').context("Shadowsocks URI has no server endpoint")?
    };
    let (method, password) = credentials.split_once(':').context("Shadowsocks credentials have no cipher/password separator")?;
    if method.is_empty() || password.is_empty() { bail!("Shadowsocks cipher and password must not be empty"); }
    let (endpoint_host, endpoint_port) = parse_endpoint(endpoint)?;
    let document = json!({
        "inbounds": [{
            "tag": "amn-socks", "listen": "127.0.0.1", "port": 10808,
            "protocol": "socks", "settings": { "auth": "noauth", "udp": true }
        }],
        "outbounds": [{
            "tag": "amn-proxy", "protocol": "shadowsocks",
            "settings": { "servers": [{
                "address": endpoint_host, "port": endpoint_port,
                "method": method, "password": password, "udp": true
            }]}
        }],
        "log": { "loglevel": "warning" }
    });
    Ok(RawConfiguration::from_parts(document, endpoint_host, endpoint_port, 0))
}

fn parse_xray_json(text: &str) -> Result<RawConfiguration> {
    let mut document: Value = serde_json::from_str(text).context("Shadowsocks XRay profile is invalid JSON")?;
    let root = document.as_object_mut().context("Shadowsocks XRay profile must be a JSON object")?;
    let outbounds = root.get_mut("outbounds").and_then(Value::as_array_mut)
        .context("Shadowsocks XRay profile has no outbounds")?;
    let (outbound_index, outbound) = outbounds.iter_mut().enumerate()
        .find(|(_, outbound)| outbound.get("protocol").and_then(Value::as_str) == Some("shadowsocks"))
        .context("Shadowsocks XRay profile has no Shadowsocks outbound")?;
    let server = outbound.pointer_mut("/settings/servers/0").and_then(Value::as_object_mut)
        .context("Shadowsocks XRay outbound has no primary server")?;
    let endpoint_host = server.get("address").and_then(Value::as_str).filter(|value| !value.is_empty())
        .context("Shadowsocks XRay server has no address")?.to_owned();
    let endpoint_port = server.get("port").and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok()).filter(|port| *port != 0)
        .context("Shadowsocks XRay server has an invalid port")?;
    for field in ["method", "password"] {
        if server.get(field).and_then(Value::as_str).is_none_or(str::is_empty) {
            bail!("Shadowsocks XRay server has no {field}");
        }
    }
    root.insert("inbounds".into(), json!([{
        "tag": "amn-socks", "listen": "127.0.0.1", "port": 10808,
        "protocol": "socks", "settings": { "auth": "noauth", "udp": true }
    }]));
    root.insert("log".into(), json!({ "loglevel": "warning" }));
    for unsupported in ["api", "metrics", "reverse", "stats", "observatory", "burstObservatory"] {
        root.remove(unsupported);
    }
    Ok(RawConfiguration::from_parts(document, endpoint_host, endpoint_port, outbound_index))
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let (host, port) = endpoint.rsplit_once(':').context("Shadowsocks endpoint has no port")?;
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() { bail!("Shadowsocks endpoint has no host"); }
    let port = port.parse::<u16>().context("Shadowsocks endpoint has an invalid port")?;
    if port == 0 { bail!("Shadowsocks endpoint has an invalid port"); }
    Ok((host.to_owned(), port))
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn accepts_xray_shadowsocks_configuration() {
        let profile = r#"{"inbounds":[{"listen":"0.0.0.0"}],"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"vpn.example","port":8388,"method":"aes-256-gcm","password":"[REDACTED]"}]}}]}"#;
        let rendered = parse(profile).unwrap().render_for_endpoint("192.0.2.3".parse().unwrap()).unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value.pointer("/inbounds/0/listen").and_then(Value::as_str), Some("127.0.0.1"));
        assert_eq!(value.pointer("/outbounds/0/settings/servers/0/address").and_then(Value::as_str), Some("192.0.2.3"));
    }

    #[test]
    fn converts_sip002_uri_to_xray() {
        use base64::Engine as _;
        let credentials = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:[REDACTED]");
        let profile = format!("ss://{credentials}@vpn.example:8388#VPN");
        let rendered = parse(&profile)
            .unwrap().render_for_endpoint("192.0.2.2".parse().unwrap()).unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value.pointer("/outbounds/0/protocol").and_then(Value::as_str), Some("shadowsocks"));
        assert_eq!(value.pointer("/outbounds/0/settings/servers/0/address").and_then(Value::as_str), Some("192.0.2.2"));
    }
}
