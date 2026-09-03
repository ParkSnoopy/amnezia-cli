package native

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type WireGuard struct {
	PrivateKey string
	Addresses  []netip.Prefix
	ListenPort uint16
	MTU        int
	Amnezia    map[string]string
	Peer       Peer
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	PersistentKeepalive string
}

func ReadWireGuard(path, protocol string) (WireGuard, error) {
	file, err := os.Open(path)
	if err != nil {
		return WireGuard{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	config := WireGuard{MTU: 1420, Amnezia: make(map[string]string)}
	section := ""
	peers := 0
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peers++
			}
			if section != "interface" && section != "peer" {
				return WireGuard{}, fmt.Errorf("line %d: unsupported section %q", lineNumber, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			return WireGuard{}, fmt.Errorf("line %d: expected key = value inside a section", lineNumber)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if err := config.apply(section, key, value, protocol); err != nil {
			return WireGuard{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return WireGuard{}, fmt.Errorf("read configuration: %w", err)
	}
	if peers != 1 {
		return WireGuard{}, fmt.Errorf("route-all mode requires exactly one peer, found %d", peers)
	}
	if config.PrivateKey == "" || config.Peer.PublicKey == "" || config.Peer.Endpoint == "" {
		return WireGuard{}, fmt.Errorf("PrivateKey, peer PublicKey, and peer Endpoint are required")
	}
	if len(config.Addresses) == 0 {
		return WireGuard{}, fmt.Errorf("Interface Address is required")
	}
	return config, nil
}

func (c *WireGuard) apply(section, key, value, protocol string) error {
	if section == "interface" {
		switch key {
		case "privatekey":
			c.PrivateKey = value
		case "address":
			for _, item := range strings.Split(value, ",") {
				prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
				if err != nil {
					return fmt.Errorf("invalid Address: %w", err)
				}
				if !prefix.Addr().Is4() {
					return fmt.Errorf("IPv6 Interface Address is not supported")
				}
				c.Addresses = append(c.Addresses, prefix)
			}
		case "listenport":
			port, err := parseUint16(value)
			if err != nil {
				return fmt.Errorf("invalid ListenPort: %w", err)
			}
			c.ListenPort = port
		case "mtu":
			mtu, err := strconv.Atoi(value)
			if err != nil || mtu < 576 || mtu > 9000 {
				return fmt.Errorf("MTU must be between 576 and 9000")
			}
			c.MTU = mtu
		case "dns":
			// The existing system resolver remains in use and is routed through amn0.
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
			"headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers", "disablecookies":
			if protocol != "amneziawg" {
				return fmt.Errorf("%s is only valid for AmneziaWG", key)
			}
			if key == "randomtrailers" || key == "disablecookies" {
				normalized, boolErr := normalizeAWGBool(value)
				if boolErr != nil {
					return fmt.Errorf("invalid %s: %w", key, boolErr)
				}
				value = normalized
			}
			c.Amnezia[key] = value
		case "preup", "postup", "predown", "postdown":
			return fmt.Errorf("configuration hooks are not allowed")
		case "table", "saveconfig":
			return fmt.Errorf("%s conflicts with managed route lifecycle", key)
		default:
			return fmt.Errorf("unsupported Interface key %q", key)
		}
		return nil
	}

	switch key {
	case "publickey":
		c.Peer.PublicKey = value
	case "presharedkey":
		c.Peer.PresharedKey = value
	case "endpoint":
		c.Peer.Endpoint = value
	case "persistentkeepalive":
		if protocol == "wireguard" {
			if _, err := parseUint16(value); err != nil {
				return fmt.Errorf("invalid PersistentKeepalive: %w", err)
			}
		} else if err := validateUint32Range(value); err != nil {
			return fmt.Errorf("invalid PersistentKeepalive: %w", err)
		}
		c.Peer.PersistentKeepalive = value
	case "allowedips":
		// Replaced by the route-all-except complement.
	default:
		return fmt.Errorf("unsupported Peer key %q", key)
	}
	return nil
}

func (c WireGuard) UAPI(allowed []netip.Prefix) (string, error) {
	privateKey, err := keyHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid PrivateKey: %w", err)
	}
	publicKey, err := keyHex(c.Peer.PublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid PublicKey: %w", err)
	}
	preshared := ""
	if c.Peer.PresharedKey != "" {
		preshared, err = keyHex(c.Peer.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("invalid PresharedKey: %w", err)
		}
	}
	endpoint, err := resolveEndpoint(c.Peer.Endpoint)
	if err != nil {
		return "", err
	}

	var output strings.Builder
	fmt.Fprintf(&output, "set=1\nprivate_key=%s\n", privateKey)
	if c.ListenPort != 0 {
		fmt.Fprintf(&output, "listen_port=%d\n", c.ListenPort)
	}
	keys := make([]string, 0, len(c.Amnezia))
	for key := range c.Amnezia {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := c.Amnezia[key]
		if key == "headerprotectionkey" {
			value, err = keyHex(value)
			if err != nil {
				return "", fmt.Errorf("invalid HeaderProtectionKey: %w", err)
			}
		}
		fmt.Fprintf(&output, "%s=%s\n", amneziaUAPIKey(key), value)
	}
	fmt.Fprintf(&output, "replace_peers=true\npublic_key=%s\n", publicKey)
	if preshared != "" {
		fmt.Fprintf(&output, "preshared_key=%s\n", preshared)
	}
	persistentKeepalive := c.Peer.PersistentKeepalive
	if persistentKeepalive == "" {
		persistentKeepalive = "0"
	}
	fmt.Fprintf(&output, "endpoint=%s\npersistent_keepalive_interval=%s\nreplace_allowed_ips=true\n", endpoint, persistentKeepalive)
	for _, prefix := range allowed {
		fmt.Fprintf(&output, "allowed_ip=%s\n", prefix)
	}
	output.WriteString("\n")
	return output.String(), nil
}

func ResolveEndpoint(value string) (string, netip.Prefix, error) {
	resolved, err := resolveEndpoint(value)
	if err != nil {
		return "", netip.Prefix{}, err
	}
	host, _, err := net.SplitHostPort(resolved)
	if err != nil {
		return "", netip.Prefix{}, err
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", netip.Prefix{}, err
	}
	if !address.Is4() {
		return "", netip.Prefix{}, fmt.Errorf("IPv6 peer Endpoint is not supported")
	}
	return resolved, netip.PrefixFrom(address, address.BitLen()), nil
}

func EndpointPrefix(endpoint string) (netip.Prefix, error) {
	_, prefix, err := ResolveEndpoint(endpoint)
	return prefix, err
}

func resolveEndpoint(value string) (string, error) {
	address, err := net.ResolveUDPAddr("udp", value)
	if err != nil {
		return "", fmt.Errorf("resolve peer Endpoint: %w", err)
	}
	return address.String(), nil
}

func keyHex(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("expected a 32-byte base64 key")
	}
	return hex.EncodeToString(decoded), nil
}

func parseUint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	return uint16(parsed), err
}

func validateUint32Range(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("expected a number or ascending range")
	}
	low, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return err
	}
	high := low
	if len(parts) == 2 {
		high, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return err
		}
	}
	if high < low {
		return fmt.Errorf("range end is lower than range start")
	}
	return nil
}

func normalizeAWGBool(value string) (string, error) {
	switch strings.ToLower(value) {
	case "on", "true", "1":
		return "true", nil
	case "off", "false", "0":
		return "false", nil
	default:
		return "", fmt.Errorf("expected on/off or true/false")
	}
}

func amneziaUAPIKey(key string) string {
	keys := map[string]string{
		"headerprotectionkey": "header_protection_key", "contentpaddingaddition": "content_padding_addition",
		"rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time",
		"keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts",
		"randomtrailers": "random_trailers", "disablecookies": "disable_cookies",
	}
	if converted, ok := keys[key]; ok {
		return converted
	}
	return key
}
