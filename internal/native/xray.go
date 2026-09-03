package native

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

func PrepareXRay(source, destination, tunName string, allowed []netip.Prefix) error {
	_, err := prepareXRay(source, destination, tunName, allowed, false)
	return err
}

func PrepareResolvedXRay(source, destination, tunName string, allowed []netip.Prefix) ([]netip.Addr, error) {
	return prepareXRay(source, destination, tunName, allowed, true)
}

func prepareXRay(source, destination, tunName string, allowed []netip.Prefix, resolveEndpoints bool) ([]netip.Addr, error) {
	content, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read XRay configuration: %w", err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("parse XRay configuration: %w", err)
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, fmt.Errorf("XRay configuration requires a non-empty outbounds array")
	}

	var endpoints []netip.Addr
	if resolveEndpoints {
		endpoints, err = resolveXRayOutbounds(outbounds)
		if err != nil {
			return nil, err
		}
	}

	routeValues := make([]string, len(allowed))
	for i, prefix := range allowed {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("XRay managed route %q is not IPv4", prefix)
		}
		routeValues[i] = prefix.String()
	}
	managedTag := "amn-tun"
	inbounds, _ := config["inbounds"].([]any)
	for _, inbound := range inbounds {
		object, ok := inbound.(map[string]any)
		if !ok || object["protocol"] != "tun" {
			continue
		}
		if tag, ok := object["tag"].(string); ok && tag != "" {
			managedTag = tag
			break
		}
	}
	tun := map[string]any{
		"tag":      managedTag,
		"port":     0,
		"protocol": "tun",
		"settings": map[string]any{
			"name":                   tunName,
			"mtu":                    1500,
			"gateway":                []string{"10.255.255.1/30"},
			"autoSystemRoutingTable": routeValues,
			"autoOutboundsInterface": "auto",
		},
	}
	managed := make([]any, 0, len(inbounds)+1)
	managed = append(managed, tun)
	for _, inbound := range inbounds {
		object, ok := inbound.(map[string]any)
		if ok && (object["tag"] == "amn-tun" || object["protocol"] == "tun") {
			continue
		}
		managed = append(managed, inbound)
	}
	config["inbounds"] = managed
	config["outbounds"] = outbounds

	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode managed XRay configuration: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(destination, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write managed XRay configuration: %w", err)
	}
	return endpoints, nil
}

func resolveXRayOutbounds(outbounds []any) ([]netip.Addr, error) {
	cache := map[string]netip.Addr{}
	unique := map[netip.Addr]struct{}{}
	for _, item := range outbounds {
		outbound, _ := item.(map[string]any)
		protocol, _ := outbound["protocol"].(string)
		settings, _ := outbound["settings"].(map[string]any)
		if settings == nil {
			continue
		}
		originalHost := firstXRayEndpointHost(settings, strings.ToLower(protocol))
		var err error
		switch strings.ToLower(protocol) {
		case "vless", "vmess":
			err = resolveAddressField(settings, "address", cache, unique)
			if err == nil {
				err = resolveAddressArray(settings, "vnext", cache, unique)
			}
		case "trojan", "shadowsocks", "socks", "http":
			err = resolveAddressField(settings, "address", cache, unique)
			if err == nil {
				err = resolveAddressArray(settings, "servers", cache, unique)
			}
		case "hysteria":
			err = resolveAddressField(settings, "address", cache, unique)
		case "wireguard":
			err = resolveWireGuardEndpoints(settings, cache, unique)
		case "freedom", "direct", "blackhole", "block", "dns", "loopback":
			// These outbounds have no fixed encrypted uplink endpoint.
		}
		if err != nil {
			return nil, fmt.Errorf("resolve XRay %s outbound: %w", protocol, err)
		}
		preserveXRayTLSServerName(outbound, originalHost)
	}
	result := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}

func firstXRayEndpointHost(settings map[string]any, protocol string) string {
	if protocol == "wireguard" {
		peers, _ := settings["peers"].([]any)
		for _, item := range peers {
			peer, _ := item.(map[string]any)
			endpoint, _ := peer["endpoint"].(string)
			host, _, err := net.SplitHostPort(endpoint)
			if err == nil {
				return host
			}
		}
		return ""
	}
	if host, _ := settings["address"].(string); host != "" {
		return host
	}
	arrayKey := "servers"
	if protocol == "vless" || protocol == "vmess" {
		arrayKey = "vnext"
	}
	items, _ := settings[arrayKey].([]any)
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if host, _ := entry["address"].(string); host != "" {
			return host
		}
	}
	return ""
}

func preserveXRayTLSServerName(outbound map[string]any, originalHost string) {
	if originalHost == "" {
		return
	}
	if _, err := netip.ParseAddr(originalHost); err == nil {
		return
	}
	stream, _ := outbound["streamSettings"].(map[string]any)
	if stream == nil || !strings.EqualFold(stringValue(stream["security"]), "tls") {
		return
	}
	tlsSettings, _ := stream["tlsSettings"].(map[string]any)
	if tlsSettings == nil {
		tlsSettings = map[string]any{}
		stream["tlsSettings"] = tlsSettings
	}
	if stringValue(tlsSettings["serverName"]) == "" {
		tlsSettings["serverName"] = originalHost
	}
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func resolveAddressArray(settings map[string]any, key string, cache map[string]netip.Addr, unique map[netip.Addr]struct{}) error {
	items, _ := settings[key].([]any)
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if entry == nil {
			continue
		}
		if err := resolveAddressField(entry, "address", cache, unique); err != nil {
			return err
		}
	}
	return nil
}

func resolveAddressField(object map[string]any, key string, cache map[string]netip.Addr, unique map[netip.Addr]struct{}) error {
	host, ok := object[key].(string)
	if !ok || host == "" {
		return nil
	}
	address, err := resolveXRayAddress(host, cache)
	if err != nil {
		return err
	}
	object[key] = address.String()
	unique[address] = struct{}{}
	return nil
}

func resolveWireGuardEndpoints(settings map[string]any, cache map[string]netip.Addr, unique map[netip.Addr]struct{}) error {
	peers, _ := settings["peers"].([]any)
	for _, item := range peers {
		peer, _ := item.(map[string]any)
		endpoint, _ := peer["endpoint"].(string)
		if endpoint == "" {
			continue
		}
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return fmt.Errorf("invalid endpoint %q", endpoint)
		}
		address, err := resolveXRayAddress(host, cache)
		if err != nil {
			return err
		}
		peer["endpoint"] = net.JoinHostPort(address.String(), port)
		unique[address] = struct{}{}
	}
	return nil
}

func resolveXRayAddress(host string, cache map[string]netip.Addr) (netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if !address.Is4() {
			return netip.Addr{}, fmt.Errorf("endpoint %q is IPv6; IPv6 is not supported", host)
		}
		return address, nil
	}
	if address, ok := cache[host]; ok {
		return address, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	var ipv4 []netip.Addr
	for _, address := range addresses {
		if address.Is4() {
			ipv4 = append(ipv4, address)
		}
	}
	if len(ipv4) == 0 {
		return netip.Addr{}, fmt.Errorf("endpoint %q has no IPv4 address", host)
	}
	sort.Slice(ipv4, func(i, j int) bool { return ipv4[i].Compare(ipv4[j]) < 0 })
	cache[host] = ipv4[0]
	return ipv4[0], nil
}
