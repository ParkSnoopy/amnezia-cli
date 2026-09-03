package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/amn-vpn/amn/internal/lifecycle"
	"github.com/amn-vpn/amn/internal/native"
	"github.com/amn-vpn/amn/internal/routes"
)

const version = "0.1.3"

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		printUsage()
		return nil
	}
	switch arguments[0] {
	case "connect":
		return connect(arguments[1:])
	case "disconnect":
		return disconnect(arguments[1:])
	case "status":
		return status(arguments[1:])
	case "routes":
		return showRoutes(arguments[1:])
	case "version", "--version", "-version":
		fmt.Printf("AmneziaVPN CLI %s\n", version)
		return nil
	case "__supervise":
		if len(arguments) != 2 {
			return errors.New("invalid internal supervisor invocation")
		}
		return lifecycle.Supervise(arguments[1])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func connect(arguments []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	protocol := flags.String("protocol", "", "xray, wireguard, or amneziawg")
	configPath := flags.String("config", "", "native protocol configuration")
	var exclusions stringList
	flags.Var(&exclusions, "exclude", "CIDR routed outside the VPN; repeatable")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *configPath == "" {
		return errors.New("usage: amn connect --protocol PROTOCOL --config FILE [--exclude CIDR ...]")
	}
	if *protocol != "xray" && *protocol != "wireguard" && *protocol != "amneziawg" {
		return fmt.Errorf("unsupported protocol %q", *protocol)
	}
	parsedExclusions, err := routes.Parse(exclusions)
	if err != nil {
		return err
	}
	var safetyBypass []string
	if sshPrefix, ok := currentSSHClient(); ok {
		safetyBypass = append(safetyBypass, sshPrefix.String())
	}
	exclusions = exclusions[:0]
	for _, prefix := range parsedExclusions {
		exclusions = append(exclusions, prefix.String())
	}

	lock, err := lifecycle.Lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := requireNoActiveConnection(); err != nil {
		return err
	}
	if _, err := net.InterfaceByName("amn0"); err == nil {
		return errors.New("interface amn0 already exists and is not owned by an active amn connection")
	}

	owner, err := randomOwner()
	if err != nil {
		return err
	}
	runtimeDir := filepath.Join(lifecycle.RuntimeRoot, owner)
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		return err
	}
	removeRuntime := true
	defer func() {
		if !removeRuntime {
			return
		}
		var recovery lifecycle.State
		if lifecycle.ReadJSON(lifecycle.RecoveryPath, &recovery) == nil && recovery.Owner == owner {
			return
		}
		_ = os.RemoveAll(runtimeDir)
	}()
	privateConfig := filepath.Join(runtimeDir, "source.conf")
	if err := lifecycle.CopyPrivate(*configPath, privateConfig); err != nil {
		return fmt.Errorf("copy private configuration: %w", err)
	}
	if err := validateNativeConfig(*protocol, privateConfig, parsedExclusions, runtimeDir); err != nil {
		return err
	}
	callerStart, err := lifecycle.ProcessStart(os.Getpid())
	if err != nil {
		return err
	}
	plan := lifecycle.Plan{
		Owner: owner, Protocol: *protocol, ConfigPath: privateConfig, Exclusions: exclusions,
		SafetyBypass: safetyBypass,
		RuntimeDir:   runtimeDir, CallerPID: os.Getpid(), CallerStart: callerStart,
	}
	planPath := filepath.Join(runtimeDir, "plan.json")
	if err := lifecycle.WriteJSON(planPath, plan, 0o600); err != nil {
		return err
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(runtimeDir, "supervisor.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	command := exec.Command(executable, "__supervise", planPath)
	command.Stdout, command.Stderr = logFile, logFile
	command.Env = []string{"PATH=", "HOME=/root", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start connection supervisor: %w", err)
	}
	supervisorStart, err := lifecycle.ProcessStart(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		logFile.Close()
		return fmt.Errorf("record connection supervisor identity: %w", err)
	}
	supervisorPID := command.Process.Pid
	logFile.Close()
	_ = command.Process.Release()

	ready, err := waitReady(runtimeDir, 15*time.Second)
	if err != nil {
		var reported supervisorStartupError
		if cleanupErr := abortStartup(owner, supervisorPID, supervisorStart, errors.As(err, &reported)); cleanupErr != nil {
			return fmt.Errorf("%w; startup cleanup failed: %v", err, cleanupErr)
		}
		return err
	}
	removeRuntime = false
	stdinInfo, err := os.Stdin.Stat()
	if err != nil || stdinInfo.Mode()&os.ModeCharDevice == 0 {
		if cleanupErr := rollbackConnection(ready); cleanupErr != nil {
			return fmt.Errorf("confirmation requires an interactive terminal; rollback failed: %w", cleanupErr)
		}
		return errors.New("confirmation requires an interactive terminal; connection was reverted")
	}

	fmt.Println("Connection is ready. Press Enter within 10 seconds to keep it.")
	confirmationTimer := time.NewTimer(10 * time.Second)
	defer confirmationTimer.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	response, err := lifecycle.SendControl(ctx, ready.ControlSocket, "arm")
	cancel()
	if err != nil || response != "armed" {
		failure := controlFailure(response, err)
		if cleanupErr := rollbackConnection(ready); cleanupErr != nil {
			return fmt.Errorf("arm confirmation failed: %s; rollback failed: %w", failure, cleanupErr)
		}
		return fmt.Errorf("arm confirmation failed: %s", failure)
	}
	entered := make(chan error, 1)
	go func() {
		_, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
		entered <- readErr
	}()
	select {
	case err := <-entered:
		if err != nil {
			if cleanupErr := rollbackConnection(ready); cleanupErr != nil {
				return fmt.Errorf("read confirmation: %w; rollback failed: %v", err, cleanupErr)
			}
			return fmt.Errorf("read confirmation: %w", err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		response, err := lifecycle.SendControl(ctx, ready.ControlSocket, "confirm")
		cancel()
		if err != nil || response != "confirmed" {
			failure := controlFailure(response, err)
			if cleanupErr := rollbackConnection(ready); cleanupErr != nil {
				return fmt.Errorf("connection confirmation failed: %s; rollback failed: %w", failure, cleanupErr)
			}
			return fmt.Errorf("connection confirmation failed: %s", failure)
		}
		fmt.Println("Connection confirmed.")
		return nil
	case <-confirmationTimer.C:
		if cleanupErr := rollbackConnection(ready); cleanupErr != nil {
			return fmt.Errorf("confirmation timed out; rollback failed: %w", cleanupErr)
		}
		return errors.New("confirmation timed out; connection was reverted")
	}
}

func controlFailure(response string, err error) string {
	if err != nil {
		return err.Error()
	}
	if response == "" {
		return "empty supervisor response"
	}
	return response
}

func abortStartup(owner string, supervisorPID int, supervisorStart uint64, allowGracefulExit bool) error {
	if allowGracefulExit {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			complete, err := startupCleanupComplete(owner, supervisorPID, supervisorStart)
			if err != nil {
				return err
			}
			if complete {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("startup supervisor cleanup did not complete; recovery evidence was retained")
	}
	if lifecycle.ProcessMatches(supervisorPID, supervisorStart) {
		_ = syscall.Kill(supervisorPID, syscall.SIGTERM)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		complete, err := startupCleanupComplete(owner, supervisorPID, supervisorStart)
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("startup supervisor cleanup did not complete; recovery evidence was retained")
}

func startupCleanupComplete(owner string, supervisorPID int, supervisorStart uint64) (bool, error) {
	var recovery lifecycle.State
	recoveryErr := lifecycle.ReadJSON(lifecycle.RecoveryPath, &recovery)
	if recoveryErr == nil && recovery.Owner != owner {
		return false, errors.New("startup recovery owner changed")
	}
	if recoveryErr != nil && !os.IsNotExist(recoveryErr) {
		return false, recoveryErr
	}
	return !lifecycle.ProcessMatches(supervisorPID, supervisorStart) && os.IsNotExist(recoveryErr), nil
}

func rollbackConnection(state lifecycle.State) error {
	responseErr := stopSupervisor(state.ControlSocket)
	if responseErr != nil && lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart) {
		_ = syscall.Kill(state.SupervisorPID, syscall.SIGTERM)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		processGone := !lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart)
		backendGone := state.BackendStart == 0 || !lifecycle.ProcessMatches(state.BackendPID, state.BackendStart)
		interfaceGone := state.InterfaceIndex == 0 || !lifecycle.InterfaceIndexExists(state.InterfaceIndex)
		stateGone, stateErr := ownerStateGone(lifecycle.StatePath, state.Owner)
		recoveryGone, recoveryErr := ownerStateGone(lifecycle.RecoveryPath, state.Owner)
		if stateErr != nil {
			return stateErr
		}
		if recoveryErr != nil {
			return recoveryErr
		}
		if processGone && backendGone && interfaceGone && stateGone && recoveryGone {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("rollback postconditions were not reached; recovery evidence was retained")
}

func ownerStateGone(path, owner string) (bool, error) {
	var state lifecycle.State
	if err := lifecycle.ReadJSON(path, &state); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	if state.Owner != owner {
		return false, fmt.Errorf("state owner changed in %s", path)
	}
	return false, nil
}

func disconnect(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("usage: amn disconnect")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	lock, err := lifecycle.Lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	var state lifecycle.State
	if err := lifecycle.ReadJSON(lifecycle.StatePath, &state); err != nil {
		if os.IsNotExist(err) {
			return disconnectRecovery()
		}
		return err
	}
	if !lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart) {
		if state.BackendStart != 0 && lifecycle.ProcessMatches(state.BackendPID, state.BackendStart) {
			return errors.New("connection supervisor is gone but the owned backend still runs; refusing incomplete cleanup")
		}
		if state.InterfaceIndex != 0 && lifecycle.InterfaceIndexExists(state.InterfaceIndex) {
			return errors.New("connection supervisor is gone but the owned interface still exists; refusing unsafe cleanup")
		}
		if err := lifecycle.CleanupBypassRoutes(state); err != nil {
			return fmt.Errorf("connection supervisor is gone but an owned bypass route remains: %w", err)
		}
		_ = lifecycle.RemoveState()
		_ = os.RemoveAll(state.RuntimeDir)
		fmt.Println("Removed stale connection state; no interface remained.")
		return nil
	}
	if err := stopSupervisor(state.ControlSocket); err != nil {
		if lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart) {
			_ = syscall.Kill(state.SupervisorPID, syscall.SIGTERM)
		}
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(lifecycle.StatePath); os.IsNotExist(err) {
			fmt.Println("Disconnected.")
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("disconnect did not complete; recovery state was retained")
}

func disconnectRecovery() error {
	var recovery lifecycle.State
	if err := lifecycle.ReadJSON(lifecycle.RecoveryPath, &recovery); err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No active connection.")
			return nil
		}
		return err
	}
	if lifecycle.ProcessMatches(recovery.SupervisorPID, recovery.SupervisorStart) {
		if recovery.ControlSocket == "" || stopSupervisor(recovery.ControlSocket) != nil {
			_ = syscall.Kill(recovery.SupervisorPID, syscall.SIGTERM)
		}
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(lifecycle.RecoveryPath); os.IsNotExist(err) {
				fmt.Println("Interrupted connection was recovered.")
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return errors.New("recovery did not complete; recovery state was retained")
	}
	if recovery.BackendStart != 0 && lifecycle.ProcessMatches(recovery.BackendPID, recovery.BackendStart) {
		return errors.New("owned backend remains without its supervisor; recovery state was retained")
	}
	if recovery.InterfaceIndex != 0 && lifecycle.InterfaceIndexExists(recovery.InterfaceIndex) {
		return errors.New("owned interface remains without its supervisor; recovery state was retained")
	}
	if err := lifecycle.CleanupBypassRoutes(recovery); err != nil {
		return fmt.Errorf("owned bypass route cleanup failed; recovery state was retained: %w", err)
	}
	if err := lifecycle.RemoveRecovery(recovery.Owner); err != nil {
		return err
	}
	_ = os.RemoveAll(recovery.RuntimeDir)
	fmt.Println("Removed completed recovery state.")
	return nil
}

func status(arguments []string) error {
	if len(arguments) != 0 {
		return errors.New("usage: amn status")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	var state lifecycle.State
	if err := lifecycle.ReadJSON(lifecycle.StatePath, &state); err != nil {
		if os.IsNotExist(err) {
			var recovery lifecycle.State
			if recoveryErr := lifecycle.ReadJSON(lifecycle.RecoveryPath, &recovery); recoveryErr == nil {
				fmt.Printf("Recovery required: interrupted %s connection\n", recovery.Protocol)
				return nil
			} else if !os.IsNotExist(recoveryErr) {
				return recoveryErr
			}
			fmt.Println("Disconnected")
			return nil
		}
		return err
	}
	iface, interfaceErr := net.InterfaceByName("amn0")
	if lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart) &&
		lifecycle.ProcessMatches(state.BackendPID, state.BackendStart) &&
		interfaceErr == nil && iface.Index == state.InterfaceIndex {
		fmt.Printf("Connected: %s on amn0\n", state.Protocol)
		return nil
	}
	fmt.Printf("Recovery required: %s state does not match the live process or interface\n", state.Protocol)
	return nil
}

func showRoutes(arguments []string) error {
	flags := flag.NewFlagSet("routes", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var exclusions stringList
	flags.Var(&exclusions, "exclude", "excluded CIDR; repeatable")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: amn routes [--exclude CIDR ...]")
	}
	parsed, err := routes.Parse(exclusions)
	if err != nil {
		return err
	}
	allowed, err := routes.Complement(parsed)
	if err != nil {
		return err
	}
	for _, prefix := range allowed {
		fmt.Println(prefix)
	}
	return nil
}

func validateNativeConfig(protocol, path string, exclusions []netip.Prefix, runtimeDir string) error {
	if protocol == "xray" {
		allowed, err := routes.Complement(exclusions)
		if err != nil {
			return err
		}
		validation := filepath.Join(runtimeDir, "validation.json")
		if err := native.PrepareXRay(path, validation, "amn0", allowed); err != nil {
			return err
		}
		return os.Remove(validation)
	}
	_, err := native.ReadWireGuard(path, protocol)
	return err
}

type supervisorStartupError struct {
	message string
}

func (err supervisorStartupError) Error() string {
	return err.message
}

func waitReady(runtimeDir string, timeout time.Duration) (lifecycle.State, error) {
	deadline := time.Now().Add(timeout)
	readyPath := filepath.Join(runtimeDir, "ready.json")
	errorPath := filepath.Join(runtimeDir, "error")
	for time.Now().Before(deadline) {
		var state lifecycle.State
		if err := lifecycle.ReadJSON(readyPath, &state); err == nil {
			return state, nil
		}
		if content, err := os.ReadFile(errorPath); err == nil {
			_ = os.WriteFile(filepath.Join(runtimeDir, "error.ack"), nil, 0o600)
			return lifecycle.State{}, supervisorStartupError{message: strings.TrimSpace(string(content))}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return lifecycle.State{}, errors.New("connection did not become ready")
}

func stopSupervisor(socket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := lifecycle.SendControl(ctx, socket, "stop")
	if err != nil {
		return err
	}
	if response != "stopping" {
		return fmt.Errorf("unexpected supervisor response %q", response)
	}
	return nil
}

func requireNoActiveConnection() error {
	var recovery lifecycle.State
	if err := lifecycle.ReadJSON(lifecycle.RecoveryPath, &recovery); err == nil {
		if lifecycle.ProcessMatches(recovery.SupervisorPID, recovery.SupervisorStart) {
			return fmt.Errorf("a %s connection is still completing recovery", recovery.Protocol)
		}
		if recovery.BackendStart != 0 && lifecycle.ProcessMatches(recovery.BackendPID, recovery.BackendStart) {
			return fmt.Errorf("a %s backend remains from an interrupted connection", recovery.Protocol)
		}
		if recovery.InterfaceIndex != 0 && lifecycle.InterfaceIndexExists(recovery.InterfaceIndex) {
			return fmt.Errorf("a %s interface remains from an interrupted connection", recovery.Protocol)
		}
		if err := lifecycle.CleanupBypassRoutes(recovery); err != nil {
			return fmt.Errorf("a %s bypass route remains from an interrupted connection: %w", recovery.Protocol, err)
		}
		if err := lifecycle.RemoveRecovery(recovery.Owner); err != nil {
			return err
		}
		_ = os.RemoveAll(recovery.RuntimeDir)
	} else if !os.IsNotExist(err) {
		return err
	}

	var state lifecycle.State
	if err := lifecycle.ReadJSON(lifecycle.StatePath, &state); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if lifecycle.ProcessMatches(state.SupervisorPID, state.SupervisorStart) {
		return fmt.Errorf("a %s connection is already active", state.Protocol)
	}
	if state.BackendStart != 0 && lifecycle.ProcessMatches(state.BackendPID, state.BackendStart) {
		return errors.New("stale connection state retains its owned backend")
	}
	if state.InterfaceIndex != 0 && lifecycle.InterfaceIndexExists(state.InterfaceIndex) {
		return errors.New("stale connection state retains its owned interface")
	}
	if err := lifecycle.CleanupBypassRoutes(state); err != nil {
		return fmt.Errorf("stale connection state retains an owned bypass route: %w", err)
	}
	_ = lifecycle.RemoveState()
	_ = os.RemoveAll(state.RuntimeDir)
	return nil
}

func currentSSHClient() (netip.Prefix, bool) {
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(fields) == 0 {
		return netip.Prefix{}, false
	}
	address, err := netip.ParseAddr(fields[0])
	if err != nil || !address.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, 32), true
}

func randomOwner() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("this command must run as root")
	}
	return nil
}

func printUsage() {
	fmt.Println(`AmneziaVPN CLI

Usage:
  amn connect --protocol PROTOCOL --config FILE [--exclude CIDR ...]
  amn disconnect
  amn status
  amn routes [--exclude CIDR ...]
  amn version`)
}
