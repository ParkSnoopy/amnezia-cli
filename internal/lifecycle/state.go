package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	RuntimeRoot  = "/run/amn"
	StateRoot    = "/var/lib/amn"
	StatePath    = StateRoot + "/state.json"
	RecoveryPath = StateRoot + "/recovery.json"
	LockPath     = RuntimeRoot + "/lock"
)

type Plan struct {
	Owner       string   `json:"owner"`
	Protocol    string   `json:"protocol"`
	ConfigPath  string   `json:"config_path"`
	Exclusions  []string `json:"exclusions"`
	RuntimeDir  string   `json:"runtime_dir"`
	CallerPID   int      `json:"caller_pid"`
	CallerStart uint64   `json:"caller_start"`
}

type State struct {
	Owner           string   `json:"owner"`
	Protocol        string   `json:"protocol"`
	RuntimeDir      string   `json:"runtime_dir"`
	ControlSocket   string   `json:"control_socket"`
	SupervisorPID   int      `json:"supervisor_pid"`
	SupervisorStart uint64   `json:"supervisor_start"`
	BackendPID      int      `json:"backend_pid"`
	BackendStart    uint64   `json:"backend_start"`
	InterfaceIndex  int      `json:"interface_index"`
	InterfaceName   string   `json:"interface_name"`
	Routes          []string `json:"routes"`
}

func EnsureDirectories() error {
	for _, path := range []string{RuntimeRoot, StateRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("protect %s: %w", path, err)
		}
	}
	return nil
}

func Lock() (*os.File, error) {
	if err := EnsureDirectories(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(LockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func WriteJSON(path string, value any, mode os.FileMode) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func RemoveState() error {
	if err := os.Remove(StatePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncStateDirectory()
}

func RemoveRecovery(owner string) error {
	var recovery State
	if err := ReadJSON(RecoveryPath, &recovery); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if recovery.Owner != owner {
		return fmt.Errorf("recovery owner changed")
	}
	if err := os.Remove(RecoveryPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncStateDirectory()
}

func syncStateDirectory() error {
	directory, err := os.Open(StateRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func ReadJSON(path string, value any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(content, value); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func CopyPrivate(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func ProcessStart(pid int) (uint64, error) {
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closing := strings.LastIndexByte(string(content), ')')
	if closing < 0 {
		return 0, errors.New("malformed process stat")
	}
	fields := strings.Fields(string(content[closing+1:]))
	if len(fields) <= 19 {
		return 0, errors.New("incomplete process stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, err
	}
	return start, nil
}

func ProcessMatches(pid int, expected uint64) bool {
	actual, err := ProcessStart(pid)
	return err == nil && actual == expected
}
