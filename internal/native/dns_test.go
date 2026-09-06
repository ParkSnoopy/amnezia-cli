package native

import (
	"reflect"
	"testing"
)

func TestWireGuardDNS(t *testing.T) {
	for _, protocol := range []string{"wireguard", "amneziawg"} {
		t.Run(protocol, func(t *testing.T) {
			path := writeConfig(t, "[Interface]\nPrivateKey = "+testKey+"\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1, vpn.example\nDNS = 8.8.8.8\n[Peer]\nPublicKey = "+testKey+"\nEndpoint = 192.0.2.1:1234\n")
			config, err := ReadWireGuard(path, protocol)
			if err != nil {
				t.Fatal(err)
			}
			want := DNS{Servers: []string{"1.1.1.1", "8.8.8.8"}, Search: []string{"vpn.example"}}
			if !reflect.DeepEqual(config.DNS, want) {
				t.Fatalf("DNS=%+v", config.DNS)
			}
		})
	}
}

func TestDNSRejectsInvalidNativeValues(t *testing.T) {
	for _, value := range []string{"::1", "2001:db8::53", "127.0.0.53", "0.0.0.0", "224.0.0.1", "", "bad domain", "bad;command", "-bad.example", "1.2.3.4\nnameserver 9.9.9.9"} {
		var d DNS
		if err := d.add(value, true); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestXRayDNSSelection(t *testing.T) {
	for _, tt := range []struct {
		name, config string
		servers      []string
		fail         bool
	}{
		{"absent", `{}`, nil, false},
		{"strings", `{"dns":{"servers":["1.1.1.1","8.8.8.8"]}}`, []string{"1.1.1.1", "8.8.8.8"}, false},
		{"mixed", `{"dns":{"servers":[{"address":"192.0.2.53","domains":["domain:internal"]},"https://dns.example/dns-query",{"address":"1.1.1.1","port":53}]}}`, []string{"1.1.1.1"}, false},
		{"encrypted-only", `{"dns":{"servers":["https://dns.example/dns-query"]}}`, nil, true},
		{"local-only", `{"dns":{"servers":["localhost"]}}`, nil, true},
		{"scoped-only", `{"dns":{"servers":[{"address":"192.0.2.53","domains":["domain:internal"]}]}}`, nil, true},
		{"custom-port", `{"dns":{"servers":[{"address":"192.0.2.53","port":5353}]}}`, nil, true},
		{"ipv6-only", `{"dns":{"servers":["2001:db8::53"]}}`, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d, err := ReadXRayDNS(writeConfig(t, tt.config))
			if (err != nil) != tt.fail {
				t.Fatalf("DNS=%+v err=%v", d, err)
			}
			if !tt.fail && !reflect.DeepEqual(d.Servers, tt.servers) {
				t.Fatalf("servers=%v", d.Servers)
			}
		})
	}
}
