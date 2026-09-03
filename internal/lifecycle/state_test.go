package lifecycle

import (
	"context"
	"io"
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
	got := runtimeEnvironment("XRAY_TUN_FD=4")
	want := []string{"PATH=", "HOME=/root", "LANG=C", "XRAY_TUN_FD=4"}
	if len(got) != len(want) {
		t.Fatalf("got %d environment entries, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("environment %d is %q, want %q", index, got[index], want[index])
		}
	}
}

func TestTrustedExecutableAcceptsBundleOwner(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "bundle")
	helperDirectory := filepath.Join(bundle, "libexec", "amn")
	if err := os.MkdirAll(helperDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	frontend := filepath.Join(bundle, "amn")
	helper := filepath.Join(helperDirectory, "xray")
	for _, path := range []string{frontend, helper} {
		if err := os.WriteFile(path, []byte("executable"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	owner := os.Getuid()
	if owner == 0 {
		owner = 12345
		for _, path := range []string{bundle, filepath.Join(bundle, "libexec"), helperDirectory, frontend, helper} {
			if err := os.Chown(path, owner, owner); err != nil {
				t.Fatal(err)
			}
		}
	}
	frontendOwner, ok := trustedExecutableOwner(frontend)
	if !ok || int(frontendOwner) != owner {
		t.Fatalf("frontend owner is %d trusted=%t, want %d", frontendOwner, ok, owner)
	}
	if !trustedExecutable(helper, frontendOwner) {
		t.Fatalf("helper owned by bundle owner %d was rejected", owner)
	}
	if err := os.Chmod(helper, 0o775); err != nil {
		t.Fatal(err)
	}
	if trustedExecutable(helper, frontendOwner) {
		t.Fatal("group-writable helper was trusted")
	}
	if err := os.Chmod(helper, 0o644); err != nil {
		t.Fatal(err)
	}
	if trustedExecutable(helper, frontendOwner) {
		t.Fatal("non-executable helper was trusted")
	}
	if err := os.Chmod(helper, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helperDirectory, 0o775); err != nil {
		t.Fatal(err)
	}
	if trustedExecutable(helper, frontendOwner) {
		t.Fatal("helper below a group-writable directory was trusted")
	}
	if err := os.Chmod(helperDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	realHelper := helper + ".real"
	if err := os.Rename(helper, realHelper); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(realHelper), helper); err != nil {
		t.Fatal(err)
	}
	if trustedExecutable(helper, frontendOwner) {
		t.Fatal("symlinked helper was trusted")
	}
	if os.Getuid() == 0 {
		if err := os.Remove(helper); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(realHelper, helper); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(helper, owner+1, owner+1); err != nil {
			t.Fatal(err)
		}
		if trustedExecutable(helper, frontendOwner) {
			t.Fatal("helper with a different owner was trusted")
		}
	}
}

func TestOpenedRuntimePinsValidatedExecutable(t *testing.T) {
	if os.Getenv("AMN_PINNED_RUNTIME_HELPER") == "1" {
		return
	}
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	runtimePath := filepath.Join(t.TempDir(), "runtime")
	destination, err := os.OpenFile(runtimePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	owner, ok := trustedExecutableOwner(runtimePath)
	if !ok {
		t.Fatal("copied runtime was not trusted")
	}
	opened, ok := openTrustedExecutable(runtimePath, owner)
	if !ok {
		t.Fatal("trusted runtime was not opened")
	}
	defer opened.Close()
	if err := os.Rename(runtimePath, runtimePath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, []byte("replacement"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/proc/self/fd/3", "-test.run=^TestOpenedRuntimePinsValidatedExecutable$")
	command.Args[0] = runtimePath
	command.ExtraFiles = []*os.File{opened}
	command.Env = append(os.Environ(), "AMN_PINNED_RUNTIME_HELPER=1", "GORACE=atexit_sleep_ms=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute pinned runtime: %v: %s", err, output)
	}
}

func TestPinnedSourceBuiltXRayExecutes(t *testing.T) {
	path := os.Getenv("AMN_TEST_XRAY")
	if path == "" {
		t.Skip("AMN_TEST_XRAY is not set")
	}
	owner, ok := trustedExecutableOwner(path)
	if !ok {
		t.Fatal("source-built XRay path was not trusted")
	}
	opened, ok := openTrustedExecutable(path, owner)
	if !ok {
		t.Fatal("source-built XRay was not opened")
	}
	defer opened.Close()
	command := exec.Command("/proc/self/fd/3", "version")
	command.Args[0] = path
	command.ExtraFiles = []*os.File{opened}
	command.Env = runtimeEnvironment()
	if output, err := command.CombinedOutput(); err != nil || len(output) == 0 {
		t.Fatalf("execute pinned source-built XRay: %v: %s", err, output)
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
