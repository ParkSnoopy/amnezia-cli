use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, bail};

use crate::core::model::{Protocol, Settings};

mod executor;

pub(crate) use executor::{
    QuickSpec,
    check_profile_dependencies,
    connect,
    disconnect,
    refresh_connection,
};

pub(crate) mod sealed {
    pub trait Sealed {}
}

pub(crate) struct PrepareRequest<'a> {
    pub source: &'a str,
    pub settings: &'a Settings,
}

pub(crate) enum ProtocolRecipe {
    Quick(QuickProgram),
    OpenVpn(crate::core::openvpn::Configuration),
    Xray(crate::core::xray::Configuration),
}

pub(crate) trait ProtocolAdapter: sealed::Sealed {
    const PROTOCOL: Protocol;

    fn prepare(request: PrepareRequest<'_>) -> Result<ProtocolRecipe>;
}

pub(crate) fn prepare_protocol(
    protocol: &Protocol,
    source: &str,
    settings: &Settings,
) -> Result<ProtocolRecipe> {
    let request = PrepareRequest {
        source,
        settings,
    };
    match protocol {
        Protocol::AmneziaWg => prepare_with::<crate::core::amneziawg::Adapter>(protocol, request),
        Protocol::WireGuard => prepare_with::<crate::core::wireguard::Adapter>(protocol, request),
        Protocol::OpenVpn => prepare_with::<crate::core::openvpn::Adapter>(protocol, request),
        Protocol::Xray => prepare_with::<crate::core::xray::Adapter>(protocol, request),
    }
}

fn prepare_with<A: ProtocolAdapter>(
    protocol: &Protocol,
    request: PrepareRequest<'_>,
) -> Result<ProtocolRecipe> {
    if A::PROTOCOL != *protocol {
        bail!("statically registered protocol adapter does not match request");
    }
    A::prepare(request)
}

pub fn validate_protocol(protocol: &Protocol, source: &str, settings: &Settings) -> Result<()> {
    prepare_protocol(protocol, source, settings).map(|_| ())
}

pub(crate) fn validate_quick_profile(source: &str) -> Result<()> {
    for key in ["PrivateKey", "PublicKey"] {
        let found = source
            .lines()
            .filter_map(|line| line.split_once('='))
            .any(|(candidate, value)| {
                candidate.trim().eq_ignore_ascii_case(key)
                    && !value.split('#').next().unwrap_or_default().trim().is_empty()
            });
        if !found {
            bail!("WireGuard profile has no {}", key.to_ascii_lowercase());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuickProgram {
    WireGuard,
    AmneziaWg,
}

impl QuickProgram {
    pub(crate) const fn executable(self) -> &'static str {
        match self {
            Self::WireGuard => "wg-quick",
            Self::AmneziaWg => "awg-quick",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuickDirection {
    Up,
    Down,
}

impl QuickDirection {
    pub(crate) const fn argument(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }

    const fn reverse(self) -> Self {
        match self {
            Self::Up => Self::Down,
            Self::Down => Self::Up,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickMutation {
    program: QuickProgram,
    direction: QuickDirection,
    profile: String,
}

impl QuickMutation {
    pub fn program(&self) -> QuickProgram {
        self.program
    }

    pub fn direction(&self) -> QuickDirection {
        self.direction
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub(crate) fn command(&self) -> (&'static str, Vec<String>) {
        (
            self.program.executable(),
            vec![self.direction.argument().into(), self.profile.clone()],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedMutation {
    Quick(QuickMutation),
    InterfaceAddress { interface: String, cidr: String },
    InterfaceState { interface: String, up: bool },
    Route { arguments: Vec<String> },
    Dns { interface: String, servers: Vec<IpAddr> },
    Firewall { family: FirewallFamily, rule: FirewallRule },
    Process { executable: String, identity: ProcessIdentity },
    PrivateFile { path: String },
    RemoteAsset { path: String, executable: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
    Inet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub table: String,
    pub chain: String,
    pub expression: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub interface: Option<String>,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversibleMutation {
    apply: TypedMutation,
    reverse: TypedMutation,
}

impl ReversibleMutation {
    pub fn quick(program: QuickProgram, direction: QuickDirection, profile: String) -> Self {
        let apply = QuickMutation {
            program,
            direction,
            profile: profile.clone(),
        };
        let reverse = QuickMutation {
            program,
            direction: direction.reverse(),
            profile,
        };
        Self {
            apply: TypedMutation::Quick(apply),
            reverse: TypedMutation::Quick(reverse),
        }
    }

    pub fn apply(&self) -> &TypedMutation {
        &self.apply
    }

    pub fn reverse(&self) -> &TypedMutation {
        &self.reverse
    }

    pub(crate) fn quick_pair(&self) -> (&QuickMutation, &QuickMutation) {
        match (&self.apply, &self.reverse) {
            (TypedMutation::Quick(apply), TypedMutation::Quick(reverse)) => (apply, reverse),
            _ => unreachable!("quick plan constructor always creates quick mutations"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightCheck {
    Root,
    TrustedExecutable(&'static str),
    InterfaceAbsent(String),
    InterfaceOwned(String),
    EndpointReachable(SocketAddr),
    DnsAvailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessProbe {
    Interface(String),
    Handshake(String),
    Process(ProcessIdentity),
    SecurityAssociation(IpAddr),
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipProbe {
    InterfacePeers { interface: String, public_keys: Vec<String> },
    Process(ProcessIdentity),
    Route { destination: String, protocol: u8 },
    SecurityAssociation(IpAddr),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TransactionPlan {
    preflight: Vec<PreflightCheck>,
    apply: Vec<ReversibleMutation>,
    readiness: Vec<ReadinessProbe>,
    ownership: Vec<OwnershipProbe>,
}

impl TransactionPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(mut self, check: PreflightCheck) -> Self {
        self.preflight.push(check);
        self
    }

    pub fn mutate(mut self, mutation: ReversibleMutation) -> Self {
        self.apply.push(mutation);
        self
    }

    pub fn require_readiness(mut self, probe: ReadinessProbe) -> Self {
        self.readiness.push(probe);
        self
    }

    pub fn prove_ownership(mut self, probe: OwnershipProbe) -> Self {
        self.ownership.push(probe);
        self
    }

    pub fn preflight(&self) -> &[PreflightCheck] {
        &self.preflight
    }

    pub fn mutations(&self) -> &[ReversibleMutation] {
        &self.apply
    }

    pub fn readiness(&self) -> &[ReadinessProbe] {
        &self.readiness
    }

    pub fn ownership(&self) -> &[OwnershipProbe] {
        &self.ownership
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_mutation_always_has_the_exact_reverse() {
        let mutation = ReversibleMutation::quick(
            QuickProgram::AmneziaWg,
            QuickDirection::Up,
            "/profiles/wg.conf".into(),
        );
        let (apply, reverse) = mutation.quick_pair();
        assert_eq!(apply.command(), ("awg-quick", vec!["up".into(), "/profiles/wg.conf".into()]));
        assert_eq!(reverse.command(), ("awg-quick", vec!["down".into(), "/profiles/wg.conf".into()]));
    }
}
