package lifecycle

import (
	"context"
	"net"
	"os"
	"os/exec"
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

func TestProcessMatchesRejectsZombie(t *testing.T) {
	if os.Getenv("AMN_ZOMBIE_HELPER") == "1" {
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestProcessMatchesRejectsZombie$")
	command.Env = append(os.Environ(), "AMN_ZOMBIE_HELPER=1", "GORACE=atexit_sleep_ms=0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	start, err := ProcessStart(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, state, err := processStat(command.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if state == "Z" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not become a zombie")
		}
		time.Sleep(time.Millisecond)
	}
	if ProcessMatches(command.Process.Pid, start) {
		t.Fatal("zombie process was treated as live identity")
	}
}

func TestRuntimeCandidatesAreExecutableRelative(t *testing.T) {
	got := runtimeCandidates("/opt/amnezia/amn", "xray")
	want := []string{
		"/opt/amnezia/libexec/amn/xray",
		"/opt/libexec/amn/xray",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("candidate %d is %q, want %q", index, got[index], want[index])
		}
	}
}

func TestRuntimeEnvironmentHasNoSearchPath(t *testing.T) {
	got := runtimeEnvironment("XRAY_TUN_FD=3")
	want := []string{"PATH=", "HOME=/root", "LANG=C", "XRAY_TUN_FD=3"}
	if len(got) != len(want) {
		t.Fatalf("got %d environment entries, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("environment %d is %q, want %q", index, got[index], want[index])
		}
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
