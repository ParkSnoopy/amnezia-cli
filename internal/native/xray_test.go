package native

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
