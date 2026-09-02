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
            disconnecting: false,
            pid: None,
            process_start_ticks: None,
            interface: Some("test".into()),
            interface_index: None,
            interface_owner: None,
            runtime_directory: None,
            quick_root_owned: false,
            xray_route: None,
            xray_owned_routes: Vec::new(),
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
    fn quick_profiles_use_configured_dns_when_import_has_no_server() {
        let settings = Settings {
            dns_servers: vec!["9.9.9.9".into(), "149.112.112.112".into()],
            ..Settings::default()
        };
        let search_only = "[Interface]\nDNS = corp.example\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        let effective = effective_quick_configuration(search_only, &settings).unwrap();
        assert!(effective.contains("DNS = 9.9.9.9, 149.112.112.112, corp.example"));
        validate_quick_dns(&effective).unwrap();

        let omitted = "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        let effective = effective_quick_configuration(omitted, &settings).unwrap();
        assert!(effective.contains("DNS = 9.9.9.9, 149.112.112.112"));
        validate_quick_dns(&effective).unwrap();

        let empty_placeholders =
            "[Interface]\nDNS = ,\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        assert!(validate_quick_dns(empty_placeholders).is_err());
        let effective = effective_quick_configuration(empty_placeholders, &settings).unwrap();
        assert!(effective.contains("DNS = 9.9.9.9, 149.112.112.112"));
        validate_quick_dns(&effective).unwrap();

        let upstream_placeholders = "[Interface]\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        let effective = effective_quick_configuration(upstream_placeholders, &settings).unwrap();
        assert!(effective.contains("DNS = 9.9.9.9, 149.112.112.112"));
        assert!(!effective.contains("$PRIMARY_DNS"));
        assert!(!effective.contains("$SECONDARY_DNS"));
        validate_quick_dns(&effective).unwrap();

        let unknown_placeholder = "[Interface]\nDNS = $UNKNOWN_DNS\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        let effective = effective_quick_configuration(unknown_placeholder, &settings).unwrap();
        assert!(validate_quick_dns(&effective).is_err());

        let profile_dns = "[Interface]\nDNS = 10.64.0.1\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = key\n";
        let effective = effective_quick_configuration(profile_dns, &settings).unwrap();
        assert!(effective.contains("DNS = 10.64.0.1"));
        assert!(!effective.contains("9.9.9.9"));
    }

    #[test]
    fn amneziawg_v3_profiles_require_bundled_userspace_backend() {
        let awg_v3 = include_str!("../../../../test/amneziawg-v3.conf");
        assert!(requires_amneziawg_userspace(awg_v3));
        let awg_legacy = include_str!("../../../../test/amneziawg-legacy.conf");
        assert!(!requires_amneziawg_userspace(awg_legacy));
    }

    #[test]
    fn exited_processes_do_not_keep_process_groups_alive() {
        let stat = fs::read_to_string(format!("/proc/{}/stat", std::process::id())).unwrap();
        let (state, group, start_ticks) = process_stat_identity(&stat).unwrap();
        assert_ne!(state, 'Z');
        assert!(start_ticks > 0);
        assert!(process_stat_is_live_group_member(&stat, group));

        let zombie = stat.replacen(&format!(") {state} "), ") Z ", 1);
        assert!(!process_stat_is_live_group_member(&zombie, group));
    }

    #[test]
    fn runtime_only_xray_recovery_has_no_network_ownership() {
        let connection = Connection {
            profile_id: "profile-a".into(),
            recovery_required: true,
            disconnecting: false,
            pid: None,
            process_start_ticks: None,
            interface: Some("amnxray0".into()),
            interface_index: None,
            interface_owner: None,
            runtime_directory: Some("/run/amn/example".into()),
            quick_root_owned: false,
            xray_route: None,
            xray_owned_routes: Vec::new(),
        };
        assert!(is_runtime_only_xray_recovery(&connection));

        let mut network_owned = connection;
        network_owned.xray_route = Some(XrayRouteIdentity {
            endpoint: "192.0.2.1".into(),
            gateway: "192.0.2.254".into(),
            uplink: "eth0".into(),
        });
        assert!(!is_runtime_only_xray_recovery(&network_owned));
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
                .any(|(forward, _)| is_xray_bypass_route(&except, forward).unwrap())
        );
        assert!(
            except_pairs
                .iter()
                .filter(|(forward, _)| forward.contains(&"0.0.0.0/1".into()))
                .all(|(forward, _)| !is_xray_bypass_route(&except, forward).unwrap())
        );
        assert!(
            except_pairs
                .iter()
                .all(|(_, reverse)| reverse.iter().any(|argument| argument == "delete"))
        );
        let bypass_reverse = except_pairs
            .iter()
            .find(|(forward, _)| is_xray_bypass_route(&except, forward).unwrap())
            .map(|(_, reverse)| reverse.clone())
            .unwrap();
        assert!(!xray_rollback_owns_route(&[], &bypass_reverse));
        assert!(xray_rollback_owns_route(
            &[XrayRollback::Ip(bypass_reverse.clone())],
            &bypass_reverse
        ));
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
        assert!(xray_route_line_matches(
            &arguments,
            "unreachable default proto 66 metric 42760 pref medium"
        )
        .unwrap());
        assert!(xray_route_line_matches(
            &arguments,
            "unreachable default dev lo proto 66 metric 42760 pref medium"
        )
        .unwrap());
        assert!(xray_route_line_matches(
            &arguments,
            "7 default dev lo proto 66 metric 42760 pref medium"
        )
        .unwrap());
        assert!(!xray_route_line_matches(
            &arguments,
            "unreachable ::/0 proto 66 metric 999 pref medium"
        )
        .unwrap());
    }

    #[test]
    fn xray_route_preflight_reuses_only_compatible_external_routes() {
        let bypass = vec![
            "route".into(),
            "add".into(),
            "192.168.0.0/16".into(),
            "via".into(),
            "192.168.1.1".into(),
            "dev".into(),
            "wlp1s0".into(),
            "proto".into(),
            "66".into(),
            "metric".into(),
            "5".into(),
        ];
        assert_eq!(
            classify_xray_route(
                &bypass,
                "192.168.0.0/16 via 192.168.1.1 dev wlp1s0"
            )
            .unwrap(),
            XrayRouteDisposition::SatisfiedExternally
        );
        assert_eq!(
            classify_xray_route(
                &bypass,
                "192.168.0.0/16 via 192.168.1.1 dev wlp1s0 proto static metric 20"
            )
            .unwrap(),
            XrayRouteDisposition::SatisfiedExternally
        );
        assert_eq!(
            classify_xray_route(
                &bypass,
                "192.168.0.0/16 via 192.168.1.1 dev wlp1s0 proto 66 metric 5"
            )
            .unwrap(),
            XrayRouteDisposition::Collision
        );
        assert_eq!(
            classify_xray_route(
                &bypass,
                "192.168.0.0/16 via 192.168.1.254 dev wlp1s0 proto static"
            )
            .unwrap(),
            XrayRouteDisposition::Collision
        );
        assert_eq!(
            classify_xray_route(&bypass, "").unwrap(),
            XrayRouteDisposition::Missing
        );
        let host_bypass = bypass
            .iter()
            .map(|argument| {
                if argument == "192.168.0.0/16" {
                    "192.168.1.25/32".to_owned()
                } else {
                    argument.clone()
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            classify_xray_route(
                &host_bypass,
                "192.168.1.25 via 192.168.1.1 dev wlp1s0 proto 3"
            )
            .unwrap(),
            XrayRouteDisposition::SatisfiedExternally
        );
        assert_eq!(
            exact_xray_route_query(&bypass).unwrap(),
            ["-N", "route", "show", "exact", "192.168.0.0/16"]
        );
        let ipv6 = ["-6", "route", "add", "unreachable", "::/0", "proto", "66"]
            .map(str::to_owned);
        assert_eq!(
            exact_xray_route_query(&ipv6).unwrap(),
            ["-N", "-6", "route", "show", "exact", "::/0"]
        );
    }

    #[test]
    fn failed_pre_identity_xray_rollback_retains_known_recovery_facts() {
        let prepared = PreparedXray {
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
            route_mode: crate::core::model::RouteMode::All,
            split_routes: Vec::new(),
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        };

        let retained = partial_xray_recovery(
            &State::default(),
            "profile-a",
            &prepared,
            u32::MAX,
            "amnxray0",
            Vec::new(),
        );
        let connection = retained.connection.unwrap();

        assert!(connection.recovery_required);
        assert_eq!(connection.profile_id, "profile-a");
        assert_eq!(connection.pid, Some(u32::MAX));
        assert_eq!(connection.interface.as_deref(), Some("amnxray0"));
        assert!(connection.interface_index.is_none());
        assert!(connection.interface_owner.is_none());
        assert_eq!(
            connection.xray_route.as_ref().map(|route| route.endpoint.as_str()),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn process_identity_uses_kernel_start_ticks() {
        let pid = std::process::id();
        let ticks = process_start_ticks(pid).expect("current process has start ticks");
        let connection = Connection {
            profile_id: "p".into(),
            recovery_required: false,
            disconnecting: false,
            pid: Some(pid),
            process_start_ticks: Some(ticks),
            interface: None,
            interface_index: None,
            interface_owner: None,
            runtime_directory: None,
            quick_root_owned: false,
            xray_route: None,
            xray_owned_routes: Vec::new(),
        };
        assert_eq!(verify_connection_process(&connection).unwrap(), pid);
        let mut mismatch = connection;
        mismatch.process_start_ticks = Some(ticks.saturating_add(1));
        assert!(verify_connection_process(&mismatch).is_err());
    }

    #[test]
    fn quick_interface_identity_does_not_depend_on_imported_filename() {
        let mut imported = profile(Protocol::AmneziaWg);
        imported.id = "12345678-1234-1234-1234-123456789abc".into();
        imported.source = "/vpn/a GUI profile name that cannot be an interface.conf".into();

        let plan = quick_connection_plan(&imported).unwrap();

        assert_eq!(plan.interface.as_deref(), Some("amn12345678123"));
        assert!(plan.interface.as_ref().unwrap().len() <= 15);
    }

    #[test]
    fn quick_disconnect_refuses_unowned_staged_cleanup() {
        let runtime = std::env::temp_dir().join(format!(
            "amn-quick-cleanup-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&runtime).unwrap();
        fs::write(runtime.join("amncleanup.conf"), b"private").unwrap();
        let mut prepared = PreparedPlan {
            program: "/tools/wg-quick".into(),
            rollback_program: "/tools/wg-quick".into(),
            args: Vec::new(),
            rollback_args: Vec::new(),
            path: "/usr/bin:/bin".into(),
            interface_probe: "/tools/wg".into(),
            ip: "/usr/bin/ip".into(),
            interface: "amncleanup".into(),
            interface_existed: true,
            expected_peer_keys: vec!["peer".into()],
            runtime_directory: Some(runtime.clone()),
            quick_base_created: false,
            uses_default_route: false,
            backend_environment: None,
            force_userspace_backend: false,
        };

        verify_quick_disconnected(&prepared).unwrap();
        assert!(prepared.cleanup_runtime().is_err());
        assert!(runtime.exists());
        fs::remove_dir_all(runtime).unwrap();
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
            uses_default_route: false,
            backend_environment: Some((
                "WG_QUICK_USERSPACE_IMPLEMENTATION".into(),
                "/tools/wireguard-go".into(),
            )),
            force_userspace_backend: true,
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
        assert_eq!(
            environment
                .get("AMN_QUICK_FORCE_USERSPACE")
                .and_then(Option::as_deref),
            Some("1")
        );
        assert_eq!(arguments.first().map(String::as_str), Some("up"));
        assert_eq!(arguments.last().map(String::as_str), Some("/vpn/amn0.conf"));

        use std::os::unix::process::ExitStatusExt;
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(256),
            stdout: Vec::new(),
            stderr: b"\x1b[31muserspace backend failed\x1b[0m\nLine unrecognized: PrivateKey = secret".to_vec(),
        };
        let failure = network_command_failure("awg-quick", &output).to_string();
        assert!(failure.contains("awg-quick exited"));
        assert!(failure.contains("userspace backend failed"));
        assert!(failure.contains("\\u{1b}"));
        assert!(failure.contains("PrivateKey=[REDACTED]"));
        assert!(!failure.contains("secret"));
    }

    #[test]
    fn disconnect_journal_retains_exact_xray_route_ownership() {
        let route = vec![
            "route".into(),
            "delete".into(),
            "0.0.0.0/1".into(),
            "dev".into(),
            "amnxray0".into(),
            "proto".into(),
            "66".into(),
            "metric".into(),
            "5".into(),
        ];
        let state = State {
            connection: Some(Connection {
                profile_id: "p".into(),
                recovery_required: false,
                disconnecting: false,
                pid: Some(42),
                process_start_ticks: Some(7),
                interface: Some("amnxray0".into()),
                interface_index: Some(11),
                interface_owner: Some("owner".into()),
                runtime_directory: None,
                quick_root_owned: false,
                xray_route: Some(XrayRouteIdentity {
                    endpoint: "192.0.2.1".into(),
                    gateway: "192.0.2.254".into(),
                    uplink: "eth0".into(),
                }),
                xray_owned_routes: vec![route.clone()],
            }),
            ..State::default()
        };

        let pending = pending_disconnect_state(&state).unwrap();
        let connection = pending.connection.as_ref().unwrap();
        assert!(connection.disconnecting);
        assert_eq!(connection.pid, Some(42));
        assert_eq!(connection.interface_index, Some(11));
        assert_eq!(connection.xray_owned_routes, vec![route]);
        validate_xray_owned_routes(connection).unwrap();

        let mut foreign = connection.clone();
        foreign.xray_owned_routes[0][4] = "foreign0".into();
        assert!(validate_xray_owned_routes(&foreign).is_err());
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
