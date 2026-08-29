use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    V4(std::net::Ipv4Addr, u8),
    V6(std::net::Ipv6Addr, u8),
}

impl Network {
    pub fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = match value.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().context("route prefix is not a number")?)),
            None => (value.trim(), None),
        };
        match address.parse::<std::net::IpAddr>().with_context(|| format!("invalid route address: {value}"))? {
            std::net::IpAddr::V4(address) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 { bail!("invalid IPv4 route prefix: {value}"); }
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                Ok(Self::V4(std::net::Ipv4Addr::from(u32::from(address) & mask), prefix))
            }
            std::net::IpAddr::V6(address) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 { bail!("invalid IPv6 route prefix: {value}"); }
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                Ok(Self::V6(std::net::Ipv6Addr::from(u128::from(address) & mask), prefix))
            }
        }
    }

    pub fn cidr(&self) -> String {
        match self {
            Self::V4(address, prefix) => format!("{address}/{prefix}"),
            Self::V6(address, prefix) => format!("{address}/{prefix}"),
        }
    }

    pub fn openvpn_route(&self, net_gateway: bool) -> String {
        let gateway = if net_gateway { " net_gateway" } else { "" };
        match self {
            Self::V4(address, prefix) => {
                let mask = std::net::Ipv4Addr::from(if *prefix == 0 { 0 } else { u32::MAX << (32 - prefix) });
                format!("route {address} {mask}{gateway}")
            }
            Self::V6(address, prefix) => format!("route-ipv6 {address}/{prefix}{gateway}"),
        }
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(..))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_routes() {
        assert_eq!(Network::parse("10.2.3.4/8").unwrap().cidr(), "10.0.0.0/8");
        assert_eq!(Network::parse("2001:db8::4/64").unwrap().cidr(), "2001:db8::/64");
    }
}
