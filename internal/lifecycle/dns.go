package lifecycle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ParkSnoopy/amnezia-cli/internal/native"
)

const resolverPath = "/etc/resolv.conf"
const maxResolverBytes = 64 * 1024

// ResolverState is compensation authority, persisted before replacement. The
// unpredictable connection marker makes applied bytes specific to this owner.
type ResolverState struct {
	Path    string `json:"path"`
	Target  string `json:"target"`
	Mode    uint32 `json:"mode"`
	Before  []byte `json:"before"`
	Applied []byte `json:"applied"`
}

func prepareDNS(path, owner string, config native.DNS) (*ResolverState, error) {
	if len(config.Servers) == 0 && len(config.Search) == 0 {
		config.Servers = []string{"1.1.1.1", "1.0.0.1"}
	}
	if len(config.Servers) == 0 {
		return nil, errors.New("DNS search domains require an IPv4 DNS server")
	}
	if owner == "" || strings.ContainsAny(owner, "\r\n") {
		return nil, errors.New("invalid DNS owner")
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve system resolver target: %w", err)
	}
	if !trustedExecutableAncestors(target, 0) {
		return nil, errors.New("resolver target has untrusted ancestor directories")
	}
	before, mode, err := readResolver(target)
	if err != nil {
		return nil, err
	}
	var applied strings.Builder
	fmt.Fprintf(&applied, "# amn DNS owner %s\n", owner)
	for _, server := range config.Servers {
		fmt.Fprintf(&applied, "nameserver %s\n", server)
	}
	if len(config.Search) != 0 {
		fmt.Fprintf(&applied, "search %s\n", strings.Join(config.Search, " "))
	}
	return &ResolverState{Path: path, Target: target, Mode: uint32(mode), Before: before, Applied: []byte(applied.String())}, nil
}

func readResolver(path string) ([]byte, os.FileMode, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, 0, errors.New("resolver target must be a root-owned regular file without group/other write access")
	}
	content, err := io.ReadAll(io.LimitReader(f, maxResolverBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(content) > maxResolverBytes {
		return nil, 0, errors.New("resolver target exceeds 64 KiB")
	}
	return content, info.Mode().Perm(), nil
}

func (d *ResolverState) current() ([]byte, error) {
	target, err := filepath.EvalSymlinks(d.Path)
	if err != nil {
		return nil, err
	}
	if target != d.Target {
		return nil, errors.New("resolver target changed; DNS recovery retained")
	}
	content, mode, err := readResolver(target)
	if err != nil {
		return nil, err
	}
	if uint32(mode) != d.Mode {
		return nil, errors.New("resolver mode changed; DNS recovery retained")
	}
	return content, nil
}

func (d *ResolverState) apply() error {
	if d == nil {
		return nil
	}
	return d.replace(d.Before, d.Applied)
}

// RestoreDNS is shared by normal teardown and every supervisor-death recovery
// path. A foreign edit is never overwritten; the caller must retain its journal.
func RestoreDNS(state State) error {
	d := state.DNS
	if d == nil {
		return nil
	}
	current, err := d.current()
	if err != nil {
		return fmt.Errorf("restore DNS: %w", err)
	}
	if bytes.Equal(current, d.Before) {
		return nil
	}
	if err := d.replace(d.Applied, d.Before); err != nil {
		return fmt.Errorf("restore DNS: %w", err)
	}
	return nil
}

func (d *ResolverState) replace(expected, replacement []byte) error {
	current, err := d.current()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return errors.New("resolver contents changed; refusing overwrite and retaining DNS recovery")
	}
	directory := filepath.Dir(d.Target)
	temporary, err := os.CreateTemp(directory, ".amn-resolver-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if err := temporary.Chmod(os.FileMode(d.Mode)); err != nil {
		return err
	}
	if _, err := temporary.Write(replacement); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Recheck after all staging I/O, immediately before the atomic rename.
	current, err = d.current()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return errors.New("resolver changed during replacement; DNS recovery retained")
	}
	if err := os.Rename(temporary.Name(), d.Target); err != nil {
		return fmt.Errorf("atomically replace resolver (bind-mounted/read-only resolver targets are unsupported): %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return err
	}
	current, err = d.current()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, replacement) {
		return errors.New("resolver changed after replacement; DNS recovery retained")
	}
	return nil
}

// Journal before application, including when application partially succeeds.
func applyDNS(state State, persist func(State) error) error {
	if state.DNS == nil {
		return nil
	}
	if err := persist(state); err != nil {
		return fmt.Errorf("persist DNS recovery: %w", err)
	}
	if err := state.DNS.apply(); err != nil {
		return fmt.Errorf("apply DNS: %w", err)
	}
	return nil
}
