package lifecycle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/amn-vpn/amn/internal/native"
)

func resolverFixture(t *testing.T) (string, *ResolverState) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned resolver fixture requires root (no host resolver is touched)")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "resolver")
	before := []byte("# original\nnameserver 192.0.2.53\noptions timeout:1\nsearch original.test\n")
	if err := os.WriteFile(target, before, 0o640); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	d, err := prepareDNS(path, "0123456789abcdef", native.DNS{Servers: []string{"198.51.100.53"}, Search: []string{"vpn.test"}})
	if err != nil {
		t.Fatal(err)
	}
	return dir, d
}

func assertResolver(t *testing.T, d *ResolverState, expected []byte) {
	t.Helper()
	content, err := os.ReadFile(d.Path)
	if err != nil || !bytes.Equal(content, expected) {
		t.Fatalf("resolver mismatch: %q, %v", content, err)
	}
	info, err := os.Stat(d.Path)
	if err != nil || uint32(info.Mode().Perm()) != d.Mode {
		t.Fatalf("resolver mode not preserved: %v", err)
	}
	if _, err := os.Readlink(d.Path); err != nil {
		t.Fatalf("resolver symlink not preserved: %v", err)
	}
}

func TestDNSJournalApplyRestoreAfterRestart(t *testing.T) {
	dir, d := resolverFixture(t)
	journal := filepath.Join(dir, "recovery.json")
	state := State{Owner: "0123456789abcdef", DNS: d}
	err := applyDNS(state, func(s State) error {
		assertResolver(t, d, d.Before)
		return WriteJSON(journal, s, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	assertResolver(t, d, d.Applied)
	var recovered State
	if err := ReadJSON(journal, &recovered); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(journal)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("journal not private")
	}
	for i := 0; i < 2; i++ {
		if err := RestoreDNS(recovered); err != nil {
			t.Fatal(err)
		}
		assertResolver(t, d, d.Before)
	}
}

func TestDNSJournalFailureDoesNotMutate(t *testing.T) {
	_, d := resolverFixture(t)
	failure := errors.New("injected journal sync failure")
	if err := applyDNS(State{DNS: d}, func(State) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("lost failure: %v", err)
	}
	assertResolver(t, d, d.Before)
}

func TestDNSLaterSetupFailureRestores(t *testing.T) {
	dir, d := resolverFixture(t)
	state := State{DNS: d}
	setup := func() (err error) {
		defer func() {
			if err != nil {
				err = errors.Join(err, RestoreDNS(state))
			}
		}()
		if err = applyDNS(state, func(s State) error { return WriteJSON(filepath.Join(dir, "recovery.json"), s, 0o600) }); err != nil {
			return err
		}
		return errors.New("injected readiness publication failure")
	}
	if err := setup(); err == nil {
		t.Fatal("setup succeeded")
	}
	assertResolver(t, d, d.Before)
}

func TestDNSRefusesForeignChanges(t *testing.T) {
	for _, change := range []string{"bytes", "target", "mode", "missing"} {
		t.Run(change, func(t *testing.T) {
			dir, d := resolverFixture(t)
			state := State{DNS: d}
			journal := filepath.Join(dir, "recovery.json")
			if err := applyDNS(state, func(s State) error { return WriteJSON(journal, s, 0o600) }); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "bytes":
				if err := os.WriteFile(d.Target, []byte("foreign\n"), 0o640); err != nil {
					t.Fatal(err)
				}
			case "target":
				other := filepath.Join(dir, "other")
				if err := os.WriteFile(other, d.Applied, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(d.Path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, d.Path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(d.Target, 0o644); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(d.Target); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(d.Path)
			if err := RestoreDNS(state); err == nil {
				t.Fatal("foreign resolver was accepted")
			}
			after, _ := os.ReadFile(d.Path)
			if !bytes.Equal(before, after) {
				t.Fatal("foreign resolver overwritten")
			}
			if _, err := os.Stat(journal); err != nil {
				t.Fatal("recovery evidence lost")
			}
		})
	}
}

func TestDNSApplyFailureRetainsJournal(t *testing.T) {
	dir, d := resolverFixture(t)
	journal := filepath.Join(dir, "recovery.json")
	err := applyDNS(State{DNS: d}, func(s State) error {
		if err := WriteJSON(journal, s, 0o600); err != nil {
			return err
		}
		return os.WriteFile(d.Target, []byte("external edit\n"), 0o640)
	})
	if err == nil {
		t.Fatal("apply accepted changed resolver")
	}
	var state State
	if err := ReadJSON(journal, &state); err != nil {
		t.Fatal(err)
	}
	if state.DNS == nil || !bytes.Equal(state.DNS.Before, d.Before) {
		t.Fatal("lost reverse authority")
	}
	content, _ := os.ReadFile(d.Target)
	if string(content) != "external edit\n" {
		t.Fatal("apply overwrote foreign resolver")
	}
}

func TestDNSMissingNativeConfigurationUsesSharedDefault(t *testing.T) {
	_, original := resolverFixture(t)
	d, err := prepareDNS(original.Path, "owner", native.DNS{})
	if err != nil {
		t.Fatal(err)
	}
	want := "# amn DNS owner owner\nnameserver 1.1.1.1\nnameserver 1.0.0.1\n"
	if string(d.Applied) != want {
		t.Fatalf("unexpected shared default: %q", d.Applied)
	}
	if err := applyDNS(State{DNS: d}, func(State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertResolver(t, d, d.Applied)
	if err := RestoreDNS(State{DNS: d}); err != nil {
		t.Fatal(err)
	}
	assertResolver(t, d, d.Before)
}

func TestDNSLegacyStateIsNoop(t *testing.T) {
	if err := applyDNS(State{}, func(State) error { t.Fatal("unnecessary journal"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDNS(State{}); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRejectsUnsafeTarget(t *testing.T) {
	_, d := resolverFixture(t)
	if err := os.Chmod(d.Target, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareDNS(d.Path, "owner", native.DNS{Servers: []string{"192.0.2.1"}}); err == nil {
		t.Fatal("writable resolver accepted")
	}
}
