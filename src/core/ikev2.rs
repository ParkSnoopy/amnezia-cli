use std::net::ToSocketAddrs;

use anyhow::{
    Context,
    Result,
    bail,
};

pub struct Configuration {
    pub host: String,
    pub endpoint: String,
    pub identity: String,
    pub remote_identity: Option<String>,
    pub certificate: Vec<u8>,
    pub password: String,
    pub ike_proposal: Option<String>,
    pub esp_proposal: Option<String>,
}

struct Fields {
    host: String,
    identity: String,
    remote_identity: Option<String>,
    certificate: Vec<u8>,
    password: String,
    ike_proposal: Option<String>,
    esp_proposal: Option<String>,
}

pub fn validate(text: &str) -> Result<()> {
    parse_fields(text).map(|_| ())
}

pub fn parse(text: &str) -> Result<Configuration> {
    let fields = parse_fields(text)?;
    let endpoint = (fields.host.as_str(), 500)
        .to_socket_addrs()
        .with_context(|| format!("resolve IKEv2 endpoint {}", fields.host))?
        .find(|address| address.is_ipv4())
        .context("IKEv2 endpoint has no IPv4 address")?
        .ip()
        .to_string();
    Ok(Configuration {
        host: fields.host,
        endpoint,
        identity: fields.identity,
        remote_identity: fields.remote_identity,
        certificate: fields.certificate,
        password: fields.password,
        ike_proposal: fields.ike_proposal,
        esp_proposal: fields.esp_proposal,
    })
}

fn parse_fields(text: &str) -> Result<Fields> {
    let document: serde_json::Value = serde_json::from_str(text)
        .context("IKEv2 profile must be an Amnezia IKEv2 JSON configuration")?;
    let mut configuration = document
        .get("ikev2_config_data")
        .cloned()
        .unwrap_or(document);
    if let Some(value) = configuration.as_str()
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value)
    {
        configuration = parsed;
    }
    if let Some(value) = configuration
        .get("config")
        .and_then(serde_json::Value::as_str)
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value)
    {
        configuration = parsed;
    }
    let configuration = &configuration;
    let android_remote = configuration
        .pointer("/remote/addr")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let host = json_string(configuration, &["hostName", "host_name", "host"])
        .or(android_remote)
        .context("IKEv2 profile has no server host")?;
    let android_identity = configuration
        .pointer("/local/id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let identity = json_string(
        configuration,
        &["userName", "user_name", "clientId", "identity"],
    )
    .or(android_identity)
    .unwrap_or_else(|| "%fromcert".into());
    let android_certificate = configuration
        .pointer("/local/p12")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let certificate = json_string(configuration, &["cert", "certificate"])
        .or(android_certificate)
        .context("IKEv2 profile has no PKCS#12 certificate")?;
    let certificate = crate::core::encoding::decode_base64(
        &certificate,
        "IKEv2 PKCS#12 certificate is not valid base64",
    )?;
    if certificate.is_empty() {
        bail!("IKEv2 PKCS#12 certificate is empty");
    }
    Ok(Fields {
        host,
        identity,
        remote_identity: json_string(configuration, &["remoteIdentity", "remote_identity"])
            .or_else(|| {
                configuration
                    .pointer("/remote/id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            }),
        certificate,
        password: json_string(configuration, &["password"])
            .or_else(|| {
                configuration
                    .pointer("/local/password")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default(),
        ike_proposal: json_string(configuration, &["ike-proposal", "ikeProposal"]),
        esp_proposal: json_string(configuration, &["esp-proposal", "espProposal"]),
    })
}

fn json_string(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_and_android_ikev2_profiles() {
        let nested = r#"{"config":"{\"hostName\":\"127.0.0.1\",\"clientId\":\"client\",\"cert\":\"AA==\"}"}"#;
        assert_eq!(parse(nested).unwrap().identity, "client");

        let android = r#"{"type":"ikev2-cert","remote":{"addr":"127.0.0.1"},"local":{"p12":"AA=="},"ike-proposal":"aes256-sha256-modp2048","esp-proposal":"aes128gcm16"}"#;
        let configuration = parse(android).unwrap();
        assert_eq!(configuration.identity, "%fromcert");
        assert_eq!(
            configuration.ike_proposal.as_deref(),
            Some("aes256-sha256-modp2048")
        );
        assert_eq!(configuration.esp_proposal.as_deref(), Some("aes128gcm16"));
    }

    #[test]
    fn parses_amnezia_ikev2_profile() {
        let profile =
            r#"{"hostName":"127.0.0.1","userName":"client","cert":"AA==","password":"[REDACTED]"}"#;
        let configuration = parse(profile).unwrap();
        assert_eq!(configuration.host, "127.0.0.1");
        assert_eq!(configuration.identity, "client");
        assert_eq!(configuration.certificate, vec![0]);
    }
}
