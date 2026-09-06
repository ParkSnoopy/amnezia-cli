package native

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// DNS is the whole-system resolver subset supported by the IPv4 tunnel.
type DNS struct {
	Servers []string
	Search  []string
}

func (d *DNS) add(value string, search bool) error {
	if ip, err := netip.ParseAddr(value); err == nil {
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("DNS requires a non-loopback unicast IPv4 server")
		}
		for _, server := range d.Servers {
			if server == ip.String() {
				return nil
			}
		}
		if len(d.Servers) == 3 {
			return fmt.Errorf("DNS supports at most three servers")
		}
		d.Servers = append(d.Servers, ip.String())
		return nil
	}
	if !search || !validSearchDomain(value) {
		return fmt.Errorf("unsupported DNS server or search domain")
	}
	if len(d.Search) == 6 {
		return fmt.Errorf("DNS supports at most six search domains")
	}
	d.Search = append(d.Search, value)
	return nil
}

func validSearchDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ReadXRayDNS selects only global, plain IPv4 port-53 servers. Domain-specific,
// encrypted, local and nonstandard-port entries remain engine-only; they cannot
// be represented in resolv.conf. Explicit unsupported DNS is rejected; an absent
// DNS configuration lets the lifecycle select its shared resolver defaults.
func ReadXRayDNS(path string) (DNS, error) {
	var config struct {
		DNS *struct {
			Servers []json.RawMessage `json:"servers"`
		} `json:"dns"`
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return DNS{}, err
	}
	if err := json.Unmarshal(content, &config); err != nil {
		return DNS{}, err
	}
	var result DNS
	if config.DNS == nil {
		return result, nil
	}
	for _, raw := range config.DNS.Servers {
		var address string
		if json.Unmarshal(raw, &address) != nil {
			var server struct {
				Address string   `json:"address"`
				Port    int      `json:"port"`
				Domains []string `json:"domains"`
			}
			if err := json.Unmarshal(raw, &server); err != nil {
				return DNS{}, fmt.Errorf("invalid XRay DNS server")
			}
			if len(server.Domains) != 0 || server.Port != 0 && server.Port != 53 {
				continue
			}
			address = server.Address
		}
		if ip, err := netip.ParseAddr(address); err != nil || !ip.Is4() {
			continue
		}
		if err := result.add(address, false); err != nil {
			return DNS{}, err
		}
	}
	if len(result.Servers) == 0 {
		return DNS{}, fmt.Errorf("XRay DNS has no global plain IPv4 port-53 server usable by the system resolver")
	}
	return result, nil
}
