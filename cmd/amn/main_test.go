package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/amn-vpn/amn/internal/lifecycle"
)

func TestReportedStartupFailureAllowsSupervisorCleanup(t *testing.T) {
	if os.Getenv("AMN_STARTUP_EXIT_HELPER") == "1" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		select {
		case <-time.After(2500 * time.Millisecond):
		case <-signals:
			os.Exit(42)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestReportedStartupFailureAllowsSupervisorCleanup$")
	command.Env = append(os.Environ(), "AMN_STARTUP_EXIT_HELPER=1", "GORACE=atexit_sleep_ms=0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	start, err := lifecycle.ProcessStart(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := abortStartup("test-owner", command.Process.Pid, start, true); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("graceful supervisor was signalled instead of allowed to exit: %v", err)
	}
}

func TestWaitReadyClassifiesReportedStartupFailure(t *testing.T) {
	runtimeDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(runtimeDirectory, "error"), []byte("runtime missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := waitReady(runtimeDirectory, time.Second)
	var reported supervisorStartupError
	if !errors.As(err, &reported) {
		t.Fatalf("startup error was not classified as supervisor-reported: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtimeDirectory, "error.ack")); err != nil {
		t.Fatalf("startup error was not acknowledged: %v", err)
	}
}
