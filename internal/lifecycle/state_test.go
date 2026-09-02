package lifecycle

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcessIdentityUsesStartTime(t *testing.T) {
	start, err := ProcessStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !ProcessMatches(os.Getpid(), start) {
		t.Fatal("current process identity did not match")
	}
	if ProcessMatches(os.Getpid(), start+1) {
		t.Fatal("changed process identity matched")
	}
}

func TestSupervisorRevertsWithoutConfirmation(t *testing.T) {
	oldTimeout := confirmationTimeout
	confirmationTimeout = 20 * time.Millisecond
	defer func() { confirmationTimeout = oldTimeout }()

	socketPath := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	start, err := ProcessStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := supervisor{
		plan:        Plan{CallerPID: os.Getpid(), CallerStart: start},
		listener:    listener,
		backendDone: make(chan error),
	}
	result := make(chan error, 1)
	go func() { result <- s.serve() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	response, err := SendControl(ctx, socketPath, "arm")
	cancel()
	if err != nil || response != "armed" {
		t.Fatalf("arm confirmation: response=%q err=%v", response, err)
	}
	err = <-result
	if err == nil || !strings.Contains(err.Error(), "confirmation timed out") {
		t.Fatalf("expected confirmation timeout, got %v", err)
	}
}

func TestWireGuardUAPIPathsMatchPinnedBackends(t *testing.T) {
	if got := wireGuardUAPIPath("wireguard", "amt123"); got != "/var/run/wireguard/amt123.sock" {
		t.Fatalf("unexpected WireGuard UAPI path %q", got)
	}
	if got := wireGuardUAPIPath("amneziawg", "amt123"); got != "/var/run/amneziawg/amt123.sock" {
		t.Fatalf("unexpected AmneziaWG UAPI path %q", got)
	}
}

func TestWriteJSONReplacesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first := State{Owner: "first"}
	second := State{Owner: "second"}
	if err := WriteJSON(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	var got State
	if err := ReadJSON(path, &got); err != nil {
		t.Fatal(err)
	}
	if got.Owner != second.Owner {
		t.Fatalf("got owner %q, want %q", got.Owner, second.Owner)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions are %o", info.Mode().Perm())
	}
}
