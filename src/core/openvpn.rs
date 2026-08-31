use anyhow::{Result, bail};

use crate::core::{
    model::{RouteMode, Settings},
    routing::Network,
};

pub(crate) struct Adapter;

impl crate::core::transaction::sealed::Sealed for Adapter {}

impl crate::core::transaction::ProtocolAdapter for Adapter {
    const PROTOCOL: crate::core::model::Protocol = crate::core::model::Protocol::OpenVpn;

    fn prepare(
        request: crate::core::transaction::PrepareRequest<'_>,
    ) -> anyhow::Result<crate::core::transaction::ProtocolRecipe> {
        Ok(crate::core::transaction::ProtocolRecipe::OpenVpn(prepare(
            request.source,
            request.settings,
        )?))
    }
}

pub struct Configuration {
    pub text: String,
    pub interface: String,
}

pub fn prepare(source: &str, settings: &Settings) -> Result<Configuration> {
    if !source.lines().any(|line| line.trim_start().starts_with("remote ")) {
        bail!("OpenVPN profile has no remote server");
    }
    let mut text = source.to_owned();
    text.push_str("\nscript-security 1\ndev amnovpn0\ndev-type tun\ndisable-dco\nblock-ipv6\ndns-updown force\n");
    match settings.route_mode {
        RouteMode::All => text.push_str("redirect-gateway def1\n"),
        RouteMode::OnlyListed => {
            text.push_str("route-nopull\n");
            append_routes(&mut text, &settings.split_routes, false)?;
        }
        RouteMode::ExceptListed => {
            text.push_str("redirect-gateway def1\n");
            append_routes(&mut text, &settings.split_routes, true)?;
        }
    }
    Ok(Configuration {
        text,
        interface: "amnovpn0".into(),
    })
}

fn append_routes(configuration: &mut String, routes: &[String], net_gateway: bool) -> Result<()> {
    for route in routes {
        configuration.push_str(&Network::parse(route)?.openvpn_route(net_gateway));
        configuration.push('\n');
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_route_mode_without_executable_hooks() {
        let mut settings = Settings {
            route_mode: RouteMode::OnlyListed,
            ..Settings::default()
        };
        settings.split_routes.push("10.0.0.0/8".into());
        let prepared = prepare("client\nremote vpn.example 1194", &settings).unwrap();
        assert!(prepared.text.contains("route-nopull"));
        assert!(prepared.text.contains("route 10.0.0.0 255.0.0.0"));
        assert!(prepared.text.contains("script-security 1"));
    }
}
