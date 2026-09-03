package lifecycle

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestNetlinkLifecycleInPrivateNamespace(t *testing.T) {
	if os.Getenv("AMN_NETLINK_HELPER") != "1" {
		unshare := ""
		for _, candidate := range []string{"/usr/bin/unshare", "/bin/unshare"} {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				unshare = candidate
				break
			}
		}
		if unshare == "" {
			t.Skip("unshare is unavailable")
		}
		probe := exec.Command(unshare, "-Urn", "/bin/true")
		if err := probe.Run(); err != nil {
			t.Skipf("private user/network namespaces are unavailable: %v", err)
		}
		command := exec.Command(unshare, "-Urn", os.Args[0], "-test.run=^TestNetlinkLifecycleInPrivateNamespace$")
		command.Env = append(os.Environ(), "AMN_NETLINK_HELPER=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("private netlink lifecycle failed: %v: %s", err, output)
		}
		return
	}

	link, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlinkRename(link.Index, "amntest"); err != nil {
		t.Fatal(err)
	}
	link, err = net.InterfaceByName("amntest")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlinkConfigure(link.Index, 1400); err != nil {
		t.Fatal(err)
	}
	link, err = net.InterfaceByName("amntest")
	if err != nil {
		t.Fatal(err)
	}
	if link.MTU != 1400 || link.Flags&net.FlagUp == 0 {
		t.Fatalf("link configuration is mtu=%d flags=%v", link.MTU, link.Flags)
	}

	address := netip.MustParsePrefix("10.42.0.1/24")
	if err := netlinkAddAddress(link.Index, address); err != nil {
		t.Fatal(err)
	}
	if err := netlinkAddAddress(link.Index, address); err == nil {
		t.Fatal("duplicate address was accepted")
	}
	addresses, err := link.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, current := range addresses {
		if current.String() == address.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("configured address %s was not observed", address)
	}

	for _, route := range []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
	} {
		if err := netlinkAddRoute(link.Index, route); err != nil {
			t.Fatal(err)
		}
		if err := netlinkAddRoute(link.Index, route); err == nil {
			t.Fatalf("duplicate route %s was accepted", route)
		}
		if err := netlinkDeleteRoute(link.Index, route); err != nil {
			t.Fatal(err)
		}
		if err := netlinkAddRoute(link.Index, route); err != nil {
			t.Fatalf("route %s was not absent after deletion: %v", route, err)
		}
		if err := netlinkDeleteRoute(link.Index, route); err != nil {
			t.Fatal(err)
		}
	}

	for value := 0; value < 300; value++ {
		route := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(value >> 8), byte(value)}), 32)
		if err := netlinkAddRoute(link.Index, route); err != nil {
			t.Fatalf("add route-dump fixture %s: %v", route, err)
		}
	}
	dump, err := netlinkQuery(
		syscall.RTM_GETROUTE,
		syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP,
		structBytes(syscall.RtMsg{Family: syscall.AF_INET, Table: syscall.RT_TABLE_MAIN}),
	)
	if err != nil {
		t.Fatalf("dump large routing table: %v", err)
	}
	dumpBytes := 0
	for _, message := range dump {
		dumpBytes += syscall.NLMSG_HDRLEN + len(message.Data)
	}
	if dumpBytes <= 8192 {
		t.Fatalf("route dump fixture was only %d bytes", dumpBytes)
	}

	defaultRoute := netip.MustParsePrefix("0.0.0.0/0")
	if err := netlinkAddRoute(link.Index, defaultRoute); err != nil {
		t.Fatal(err)
	}
	bypass, err := netlinkLookupBypassRoute(netip.MustParseAddr("203.0.113.7"), 42666)
	if err != nil {
		t.Fatal(err)
	}
	if bypass.InterfaceIndex != link.Index || bypass.Destination != "203.0.113.7/32" || bypass.Gateway != "" {
		t.Fatalf("unexpected original route: %#v", bypass)
	}
	if err := netlinkAddBypassRoute(bypass); err != nil {
		t.Fatal(err)
	}
	if exists, err := netlinkBypassRouteExists(bypass); err != nil || !exists {
		t.Fatalf("owned bypass route was not observed: exists=%v err=%v", exists, err)
	}
	if err := netlinkAddBypassRoute(bypass); err == nil {
		t.Fatal("duplicate bypass route was accepted")
	}
	wrongIdentity := bypass
	wrongIdentity.Priority++
	if err := CleanupBypassRoutes(State{BypassRoutes: []BypassRoute{wrongIdentity}}); err != nil {
		t.Fatalf("cleanup rejected absent foreign identity: %v", err)
	}
	if exists, err := netlinkBypassRouteExists(bypass); err != nil || !exists {
		t.Fatalf("cleanup mutated a route with different identity: exists=%v err=%v", exists, err)
	}
	if err := CleanupBypassRoutes(State{BypassRoutes: []BypassRoute{bypass}}); err == nil {
		t.Fatal("cleanup deleted a route whose successful creation was not recorded")
	}
	if exists, err := netlinkBypassRouteExists(bypass); err != nil || !exists {
		t.Fatalf("unconfirmed route was mutated: exists=%v err=%v", exists, err)
	}
	bypass.Applied = true
	if err := CleanupBypassRoutes(State{BypassRoutes: []BypassRoute{bypass}}); err != nil {
		t.Fatal(err)
	}
	if exists, err := netlinkBypassRouteExists(bypass); err != nil || exists {
		t.Fatalf("owned bypass route remained: exists=%v err=%v", exists, err)
	}
	if err := netlinkDeleteRoute(link.Index, defaultRoute); err != nil {
		t.Fatal(err)
	}
}
