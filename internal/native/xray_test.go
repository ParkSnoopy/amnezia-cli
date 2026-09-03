package native

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareXRayPreservesOutboundsAndReplacesManagedTun(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	destination := filepath.Join(dir, "managed.json")
	input := `{"inbounds":[{"tag":"amn-tun","protocol":"socks"},{"tag":"legacy-tun","protocol":"tun"},{"tag":"local","protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}`
	if err := os.WriteFile(source, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareXRay(source, destination, "amt123456789012", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 2 || inbounds[0].(map[string]any)["protocol"] != "tun" {
		t.Fatalf("unexpected inbounds: %#v", inbounds)
	}
	settings := inbounds[0].(map[string]any)["settings"].(map[string]any)
	gateways := settings["gateway"].([]any)
	if len(gateways) != 1 || gateways[0] != "10.255.255.1/30" {
		t.Fatalf("unexpected IPv4-only gateways: %#v", gateways)
	}
	if len(config["outbounds"].([]any)) != 1 {
		t.Fatal("outbounds changed")
	}
}

func TestPreparedXRayConfigurationIsAcceptedBySourceBuild(t *testing.T) {
	binary := os.Getenv("AMN_TEST_XRAY")
	if binary == "" {
		t.Skip("AMN_TEST_XRAY is not set")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source.json")
	destination := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(source, []byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareXRay(source, destination, "amt123456789012", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-test", "-config", destination)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("source-built XRay rejected managed configuration: %v: %s", err, output)
	}
}

func TestPrepareResolvedXRayPinsProxyEndpoint(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.json")
	destination := filepath.Join(directory, "managed.json")
	config := `{
  "outbounds": [
    {"protocol":"vless","settings":{"vnext":[{"address":"198.51.100.17","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]}},
    {"protocol":"freedom","settings":{}}
  ]
}`
	if err := os.WriteFile(source, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoints, err := PrepareResolvedXRay(source, destination, "amn0", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0] != netip.MustParseAddr("198.51.100.17") {
		t.Fatalf("unexpected pinned endpoints: %v", endpoints)
	}
	var managed map[string]any
	content, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &managed); err != nil {
		t.Fatal(err)
	}
	outbound := managed["outbounds"].([]any)[0].(map[string]any)
	vnext := outbound["settings"].(map[string]any)["vnext"].([]any)
	if address := vnext[0].(map[string]any)["address"]; address != "198.51.100.17" {
		t.Fatalf("managed endpoint is %v", address)
	}
	if binary := os.Getenv("AMN_TEST_XRAY"); binary != "" {
		command := exec.Command(binary, "run", "-test", "-config", destination)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("source-built XRay rejected resolved managed configuration: %v: %s", err, output)
		}
	}
}

func TestPinnedXRayEndpointPreservesImplicitTLSServerName(t *testing.T) {
	outbound := map[string]any{
		"streamSettings": map[string]any{
			"security":    "tls",
			"tlsSettings": map[string]any{},
		},
	}
	preserveXRayTLSServerName(outbound, "vpn.example.com")
	stream := outbound["streamSettings"].(map[string]any)
	tlsSettings := stream["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "vpn.example.com" {
		t.Fatalf("implicit TLS server name was not preserved: %#v", tlsSettings)
	}
}

func TestPrepareResolvedXRayRejectsIPv6Endpoint(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.json")
	if err := os.WriteFile(source, []byte(`{"outbounds":[{"protocol":"vless","settings":{"address":"2001:db8::1","port":443}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareResolvedXRay(source, filepath.Join(directory, "managed.json"), "amn0", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err == nil || !strings.Contains(err.Error(), "IPv6 is not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}
