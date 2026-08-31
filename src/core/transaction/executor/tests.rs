#[cfg(test)]
mod tests {
    use super::*;

    fn profile(protocol: Protocol) -> Profile {
        Profile {
            id: "p".into(),
            name: "test".into(),
            protocol,
            source: "/vpn/test.conf".into(),
            enabled: true,
        }
    }

    #[test]
    fn network_plans_always_include_opposite_rollback() {
        let connect = quick_connection_plan(&profile(Protocol::WireGuard)).unwrap();
        let ((_, connect_args), (_, connect_rollback)) = connect.commands();
        assert_eq!(connect_args.first().map(String::as_str), Some("up"));
        assert_eq!(connect_rollback.first().map(String::as_str), Some("down"));

        let connection = Connection {
            profile_id: "p".into(),
            recovery_required: false,
            pid: None,
            process_start_ticks: None,
            interface: Some("test".into()),
            interface_index: None,
            interface_owner: None,
            runtime_directory: None,
            xray_route: None,
        };
        let disconnect = disconnect_plan(&profile(Protocol::WireGuard), &connection).unwrap();
        let ((_, disconnect_args), (_, disconnect_rollback)) = disconnect.commands();
        assert_eq!(disconnect_args.first().map(String::as_str), Some("down"));
        assert_eq!(disconnect_rollback.first().map(String::as_str), Some("up"));
    }

    #[test]
    fn configuration_dependencies_are_detected() {
        let configuration = "[Interface]\nDNS = 1.1.1.1 # resolver\n[Peer]\nAllowedIPs = 10.0.0.0/8, 0:0:0:0:0:0:0:0/0 # default\n";
        assert!(configuration_has_key(configuration, "dns"));
        validate_quick_dns(configuration).unwrap();
        assert!(validate_quick_dns("DNS = example.test").is_err());
        assert!(configuration_has_default_route(configuration));
        assert!(!configuration_has_default_route(
            "AllowedIPs = 10.0.0.0/8 # ::/0"
        ));
    }

    #[test]
    fn rollback_only_restores_changed_interface_ownership_state() {
        assert_eq!(rollback_strategy(false, false), RollbackStrategy::None);
        assert_eq!(rollback_strategy(false, true), RollbackStrategy::Opposite);
        assert_eq!(rollback_strategy(true, false), RollbackStrategy::Opposite);
        assert_eq!(
            rollback_strategy(true, true),
            RollbackStrategy::NormalizeThenOpposite
        );

        let expected = vec!["peer-a".to_owned(), "peer-b".to_owned()];
        assert!(peer_sets_match(&expected, ["peer-b", "peer-a"].into_iter()));
        assert!(!peer_sets_match(&expected, ["peer-a"].into_iter()));
        assert!(!peer_sets_match(
            &expected,
            ["peer-a", "peer-b", "peer-c"].into_iter()
        ));
    }

    #[test]
    fn xray_route_modes_generate_distinct_reversible_routes() {
        let prepared = |route_mode, split_routes| {
            PreparedXray {
                configuration: String::new(),
                endpoint: "192.0.2.1".into(),
                endpoint_port: 443,
                requires_tcp_endpoint: true,
                gateway: "192.0.2.254".into(),
                uplink: "eth0".into(),
                executable: "/bundle/xray".into(),
                tun2socks: "/bundle/tun2socks".into(),
                setsid: "/usr/bin/setsid".into(),
                kill: "/usr/bin/kill".into(),
                ip: "/usr/bin/ip".into(),
                dns_helper: "/bundle/amn-dns".into(),
                path: "/usr/bin".into(),
                route_mode,
                split_routes,
                dns_servers: vec!["1.1.1.1".parse().unwrap()],
            }
        };
        let only = prepared(
            crate::core::model::RouteMode::OnlyListed,
            vec![crate::core::routing::Network::parse("10.4.3.2/8").unwrap()],
        );
        let only_pairs = traffic_route_pairs(&only, "amnxray0");
        assert_eq!(only_pairs.len(), 1);
        assert!(only_pairs[0].0.contains(&"10.0.0.0/8".into()));
        assert!(!only_pairs[0].0.contains(&"0.0.0.0/1".into()));

        let except = prepared(
            crate::core::model::RouteMode::ExceptListed,
            vec![crate::core::routing::Network::parse("10.0.0.0/8").unwrap()],
        );
        let except_pairs = traffic_route_pairs(&except, "amnxray0");
        assert!(
            except_pairs
                .iter()
                .any(|(forward, _)| forward.contains(&"0.0.0.0/1".into()))
        );
        assert!(except_pairs.iter().any(|(forward, _)| {
            forward.contains(&"10.0.0.0/8".into()) && forward.contains(&"eth0".into())
        }));
        assert!(
            except_pairs
                .iter()
                .all(|(_, reverse)| reverse.iter().any(|argument| argument == "delete"))
        );
    }

    #[test]
    fn xray_route_matching_handles_ipv6_unreachable_routes() {
        let arguments = vec![
            "-6".into(),
            "route".into(),
            "delete".into(),
            "unreachable".into(),
            "::/0".into(),
            "proto".into(),
            "66".into(),
            "metric".into(),
            "42760".into(),
        ];
        assert!(xray_route_line_matches(
            &arguments,
            "unreachable ::/0 proto 66 metric 42760 pref medium"
        )
        .unwrap());
        assert!(!xray_route_line_matches(
            &arguments,
            "unreachable ::/0 proto 66 metric 999 pref medium"
        )
        .unwrap());
    }

    #[test]
    fn process_identity_uses_kernel_start_ticks() {
        let pid = std::process::id();
        let ticks = process_start_ticks(pid).expect("current process has start ticks");
        let connection = Connection {
            profile_id: "p".into(),
            recovery_required: false,
            pid: Some(pid),
            process_start_ticks: Some(ticks),
            interface: None,
            interface_index: None,
            interface_owner: None,
            runtime_directory: None,
            xray_route: None,
        };
        assert_eq!(verify_connection_process(&connection).unwrap(), pid);
        let mut mismatch = connection;
        mismatch.process_start_ticks = Some(ticks.saturating_add(1));
        assert!(verify_connection_process(&mismatch).is_err());
    }

    #[test]
    fn root_network_command_uses_validated_dependency_environment() {
        let prepared = PreparedPlan {
            program: "/tools/wg-quick".into(),
            rollback_program: "/tools/wg-quick".into(),
            args: Vec::new(),
            rollback_args: Vec::new(),
            path: "/bundle:/usr/bin".into(),
            interface_probe: "/tools/wg".into(),
            ip: "/tools/ip".into(),
            interface: "amn0".into(),
            interface_existed: false,
            expected_peer_keys: vec!["peer".into()],
            runtime_directory: None,
            quick_base_created: false,
            backend_environment: Some((
                "WG_QUICK_USERSPACE_IMPLEMENTATION".into(),
                "/tools/wireguard-go".into(),
            )),
        };
        let command = network_command(
            &prepared.program,
            &["up".into(), "/vpn/amn0.conf".into()],
            &prepared,
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            environment.get("PATH").and_then(Option::as_deref),
            Some("/bundle:/usr/bin")
        );
        assert_eq!(
            environment
                .get("WG_QUICK_USERSPACE_IMPLEMENTATION")
                .and_then(Option::as_deref),
            Some("/tools/wireguard-go")
        );
        assert_eq!(arguments.first().map(String::as_str), Some("up"));
        assert_eq!(arguments.last().map(String::as_str), Some("/vpn/amn0.conf"));
    }

    #[test]
    fn bundled_programs_are_resolved_relative_to_the_running_binary() {
        assert_eq!(
            executable_relative_program_directories(Path::new("/opt/amn/amn")),
            vec![
                PathBuf::from("/opt/amn/libexec/amn"),
                PathBuf::from("/opt/amn/../libexec/amn"),
            ]
        );
        assert!(is_bundled_network_program("wireguard-go"));
        assert!(is_bundled_network_program("amnezia-xray-runner"));
        assert!(is_bundled_network_program("amn-dns"));
        assert!(!is_bundled_network_program("resolvectl"));
        assert!(!is_bundled_network_program("resolvconf"));
        assert!(!is_bundled_network_program("ip"));
    }
}
