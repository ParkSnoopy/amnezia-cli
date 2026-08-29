use anyhow::{Context, Result, bail};

use std::net::ToSocketAddrs;

pub struct Configuration {
    pub host: String,
    pub endpoint: String,
    pub identity: String,
    pub remote_identity: Option<String>,
    pub certificate: Vec<u8>,
    pub password: String,
}

pub fn validate(text: &str) -> Result<()> {
    parse_fields(text).map(|_| ())
}

pub fn parse(text: &str) -> Result<Configuration> {
    let (host, identity, remote_identity, certificate, password) = parse_fields(text)?;
    let endpoint = (host.as_str(), 500).to_socket_addrs()
        .with_context(|| format!("resolve IKEv2 endpoint {host}"))?
        .find(|address| address.is_ipv4()).context("IKEv2 endpoint has no IPv4 address")?.ip().to_string();
    Ok(Configuration { host, endpoint, identity, remote_identity, certificate, password })
}

fn parse_fields(text: &str) -> Result<(String, String, Option<String>, Vec<u8>, String)> {
    let document: serde_json::Value = serde_json::from_str(text)
        .context("IKEv2 profile must be an Amnezia IKEv2 JSON configuration")?;
    let configuration = document.get("ikev2_config_data").unwrap_or(&document);
    let host = json_string(configuration, &["hostName", "host_name", "host"])
        .context("IKEv2 profile has no server host")?;
    let identity = json_string(configuration, &["userName", "user_name", "identity"])
        .context("IKEv2 profile has no client identity")?;
    let certificate = json_string(configuration, &["cert", "certificate"])
        .context("IKEv2 profile has no PKCS#12 certificate")?;
    let certificate = crate::core::encoding::decode_base64(
        &certificate,
        "IKEv2 PKCS#12 certificate is not valid base64",
    )?;
    if certificate.is_empty() { bail!("IKEv2 PKCS#12 certificate is empty"); }
    Ok((
        host,
        identity,
        json_string(configuration, &["remoteIdentity", "remote_identity"]),
        certificate,
        json_string(configuration, &["password"]).unwrap_or_default(),
    ))
}

fn json_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty()).map(str::to_owned)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_amnezia_ikev2_profile() {
        let profile = r#"{"hostName":"127.0.0.1","userName":"client","cert":"AA==","password":"secret"}"#;
        let configuration = parse(profile).unwrap();
        assert_eq!(configuration.host, "127.0.0.1");
        assert_eq!(configuration.identity, "client");
        assert_eq!(configuration.certificate, vec![0]);
    }
}
