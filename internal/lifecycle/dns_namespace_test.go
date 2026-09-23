package lifecycle

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Exercise the real supervisor cleanup, not a model of its compensation. Mount
// private state roots before calling any production lifecycle entry point.
func TestDNSCleanupInPrivateNamespace(t *testing.T) {
	if os.Getenv("AMN_DNS_HELPER") != "1" {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("unshare unavailable")
		}
		if err := exec.Command(unshare, "-Urnm", "/bin/true").Run(); err != nil {
			t.Skipf("private namespaces unavailable: %v", err)
		}
		command := exec.Command(unshare, "-Urnm", os.Args[0], "-test.run=^TestDNSCleanupInPrivateNamespace$", "-test.v")
		command.Env = append(os.Environ(), "AMN_DNS_HELPER=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated DNS cleanup: %v\n%s", err, output)
		} else {
			t.Log(string(output))
		}
		return
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/run", "/var/lib"} {
		if err := syscall.Mount("tmpfs", path, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700"); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsureDirectories(); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"later-startup-failure", "confirmed-disconnect", "foreign-edit", "bind-mounted-target", "restore-write-failure"} {
		t.Run(scenario, func(t *testing.T) {
			_, d := resolverFixture(t)
			runtime, err := os.MkdirTemp(RuntimeRoot, "dns-")
			if err != nil {
				t.Fatal(err)
			}
			state := State{Owner: "0123456789abcdef", RuntimeDir: runtime, DNS: d}
			s := supervisor{state: state, plan: Plan{Owner: state.Owner, RuntimeDir: runtime}}
			if scenario == "bind-mounted-target" {
				if err := syscall.Mount(d.Target, d.Target, "", syscall.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				defer syscall.Unmount(d.Target, 0)
			}
			applyErr := applyDNS(state, func(s State) error { return WriteJSON(RecoveryPath, s, 0o600) })
			if scenario == "bind-mounted-target" {
				if applyErr == nil {
					t.Fatal("bind-mounted resolver unexpectedly replaced")
				}
				assertResolver(t, d, d.Before)
				var recovery State
				if err := ReadJSON(RecoveryPath, &recovery); err != nil || recovery.DNS == nil {
					t.Fatal("application failure lost journal", err)
				}
			} else if applyErr != nil {
				t.Fatal(applyErr)
			}
			if scenario == "confirmed-disconnect" {
				if err := WriteJSON(StatePath, state, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := RemoveRecovery(state.Owner); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "foreign-edit" {
				if err := os.WriteFile(d.Target, []byte("foreign\n"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "restore-write-failure" {
				if err := syscall.Mount(d.Target, d.Target, "", syscall.MS_BIND, ""); err != nil {
					t.Fatal(err)
				}
				s.cleanup()
				assertResolver(t, d, d.Applied)
				var recovery State
				if err := ReadJSON(RecoveryPath, &recovery); err != nil || recovery.DNS == nil {
					t.Fatal("restore failure lost journal", err)
				}
				if _, err := os.Stat(runtime); err != nil {
					t.Fatal("restore failure lost runtime", err)
				}
				if err := syscall.Unmount(d.Target, 0); err != nil {
					t.Fatal(err)
				}
			}
			// This is the production defer reached on startup/serve/confirmation failure.
			s.cleanup()
			if scenario == "foreign-edit" {
				var recovery State
				if err := ReadJSON(RecoveryPath, &recovery); err != nil {
					t.Fatal("lost recovery journal", err)
				}
				if recovery.DNS == nil {
					t.Fatal("lost DNS authority")
				}
				if _, err := os.Stat(runtime); err != nil {
					t.Fatal("lost runtime evidence")
				}
				current, _ := os.ReadFile(d.Path)
				if !bytes.Equal(current, []byte("foreign\n")) {
					t.Fatal("overwrote external edit")
				}
				// A recovered original file permits the same production cleanup to finish.
				if err := os.WriteFile(d.Target, d.Before, 0o640); err != nil {
					t.Fatal(err)
				}
				s.cleanup()
			}
			assertResolver(t, d, d.Before)
			for _, path := range []string{RecoveryPath, StatePath, runtime} {
				if _, err := os.Stat(filepath.Clean(path)); !os.IsNotExist(err) {
					t.Fatalf("cleanup left %s: %v", path, err)
				}
			}
		})
	}
}
