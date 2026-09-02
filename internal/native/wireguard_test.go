package native

import (
	"os"
	"strings"
	"testing"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestReadWireGuardReplacesAllowedIPs(t *testing.T) {
	path := writeConfig(t, `[Interface]
PrivateKey = `+testKey+`
Address = 10.8.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = `+testKey+`
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.0.0.0/8
`)
	config, err := ReadWireGuard(path, "wireguard")
	if err != nil {
		t.Fatal(err)
	}
	request, err := config.UAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(request, "10.0.0.0/8") {
		t.Fatal("upstream AllowedIPs was not replaced")
	}
}

func TestReadWireGuardRejectsHooks(t *testing.T) {
	path := writeConfig(t, `[Interface]
PrivateKey = `+testKey+`
Address = 10.8.0.2/32
PostUp = touch /tmp/not-allowed
[Peer]
PublicKey = `+testKey+`
Endpoint = 127.0.0.1:51820
`)
	if _, err := ReadWireGuard(path, "wireguard"); err == nil || !strings.Contains(err.Error(), "hooks") {
		t.Fatalf("expected hook rejection, got %v", err)
	}
}

func TestReadAmneziaWGAcceptsRangeKeepalive(t *testing.T) {
	path := writeConfig(t, `[Interface]
PrivateKey = `+testKey+`
Address = 10.8.0.2/32
Jc = 4
HeaderProtectionKey = `+testKey+`
RandomTrailers = on
DisableCookies = off
[Peer]
PublicKey = `+testKey+`
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 22-30
`)
	config, err := ReadWireGuard(path, "amneziawg")
	if err != nil {
		t.Fatal(err)
	}
	request, err := config.UAPI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(request, "persistent_keepalive_interval=22-30") {
		t.Fatal("AmneziaWG keepalive range was not preserved")
	}
	if !strings.Contains(request, "header_protection_key="+strings.Repeat("0", 64)) {
		t.Fatal("AmneziaWG header key was not converted to UAPI hex")
	}
	if !strings.Contains(request, "random_trailers=true") || !strings.Contains(request, "disable_cookies=false") {
		t.Fatal("AmneziaWG native Boolean values were not normalized for UAPI")
	}
}

func TestWireGuardRejectsIPv6InterfaceAddress(t *testing.T) {
	config := WireGuard{}
	if err := config.apply("interface", "address", "fd00::1/64", "wireguard"); err == nil {
		t.Fatal("expected IPv6 interface address rejection")
	}
}

func TestResolveEndpointRejectsIPv6(t *testing.T) {
	if _, _, err := ResolveEndpoint("[::1]:51820"); err == nil {
		t.Fatal("expected IPv6 endpoint rejection")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "config-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}
