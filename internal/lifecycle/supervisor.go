package lifecycle

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amn-vpn/amn/internal/native"
	"github.com/amn-vpn/amn/internal/routes"
)

type supervisor struct {
	plan        Plan
	state       State
	backend     *exec.Cmd
	backendDone chan error
	listener    *net.UnixListener
	confirmed   bool
	tunFile     *os.File
	tunName     string
	tunIndex    int
}

type controlRequest struct {
	command string
	conn    net.Conn
}

var confirmationTimeout = 10 * time.Second

func Supervise(planPath string) error {
	var plan Plan
	if err := ReadJSON(planPath, &plan); err != nil {
		return err
	}
	if plan.Owner == "" || plan.RuntimeDir == "" || filepath.Dir(planPath) != plan.RuntimeDir {
		return errors.New("invalid supervisor plan")
	}
	if !ProcessMatches(plan.CallerPID, plan.CallerStart) {
		return errors.New("connect caller is no longer running")
	}

	supervisorStart, err := ProcessStart(os.Getpid())
	if err != nil {
		return err
	}
	if _, err := os.Stat(RecoveryPath); err == nil {
		return errors.New("another recovery journal already exists")
	} else if !os.IsNotExist(err) {
		return err
	}
	s := &supervisor{
		plan: plan,
		state: State{
			Owner: plan.Owner, Protocol: plan.Protocol, RuntimeDir: plan.RuntimeDir,
			SupervisorPID: os.Getpid(), SupervisorStart: supervisorStart,
		},
	}
	if err := WriteJSON(RecoveryPath, s.state, 0o600); err != nil {
		return fmt.Errorf("write recovery intent: %w", err)
	}
	defer s.cleanup()
	if err := s.start(); err != nil {
		errorPath := filepath.Join(plan.RuntimeDir, "error")
		_ = os.WriteFile(errorPath, []byte(err.Error()+"\n"), 0o600)
		ackPath := filepath.Join(plan.RuntimeDir, "error.ack")
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && ProcessMatches(plan.CallerPID, plan.CallerStart) {
			if _, ackErr := os.Stat(ackPath); ackErr == nil {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		return err
	}
	return s.serve()
}

func (s *supervisor) start() error {
	prefixes, err := routes.Parse(s.plan.Exclusions)
	if err != nil {
		return err
	}
	var allowed []netip.Prefix
	if s.plan.Protocol == "wireguard" || s.plan.Protocol == "amneziawg" {
		config, err := native.ReadWireGuard(s.plan.ConfigPath, s.plan.Protocol)
		if err != nil {
			return err
		}
		resolvedEndpoint, endpoint, err := native.ResolveEndpoint(config.Peer.Endpoint)
		if err != nil {
			return err
		}
		config.Peer.Endpoint = resolvedEndpoint
		prefixes = append(prefixes, endpoint)
		hasIPv4, hasIPv6 := false, false
		for _, address := range config.Addresses {
			hasIPv4 = hasIPv4 || address.Addr().Is4()
			hasIPv6 = hasIPv6 || address.Addr().Is6()
		}
		if !hasIPv4 {
			prefixes = append(prefixes, netip.MustParsePrefix("0.0.0.0/0"))
		}
		if !hasIPv6 {
			prefixes = append(prefixes, netip.MustParsePrefix("::/0"))
		}
		allowed, err = routes.Complement(prefixes)
		if err != nil {
			return err
		}
		if err := s.setPlannedRoutes(allowed); err != nil {
			return err
		}
		if err := s.startWireGuard(config, allowed); err != nil {
			return err
		}
	} else if s.plan.Protocol == "xray" {
		allowed, err = routes.Complement(prefixes)
		if err != nil {
			return err
		}
		if err := s.setPlannedRoutes(allowed); err != nil {
			return err
		}
		if err := s.startXRay(allowed); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported protocol %q", s.plan.Protocol)
	}

	if s.state.InterfaceName != "amn0" {
		if err := s.renameTun(); err != nil {
			return err
		}
	}
	iface, err := waitInterface("amn0", 5*time.Second)
	if err != nil {
		return err
	}
	if iface.Index != s.tunIndex {
		return errors.New("managed TUN identity changed during rename")
	}
	socketPath := filepath.Join(s.plan.RuntimeDir, "control.sock")
	address := &net.UnixAddr{Name: socketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return fmt.Errorf("create control socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		return err
	}
	s.listener = listener
	s.state.ControlSocket = socketPath
	s.state.InterfaceIndex = iface.Index
	s.state.InterfaceName = "amn0"
	if err := WriteJSON(RecoveryPath, s.state, 0o600); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(s.plan.RuntimeDir, "ready.json"), s.state, 0o600)
}

func (s *supervisor) startXRay(allowed []netip.Prefix) error {
	xray, err := RuntimeExecutable("xray")
	if err != nil {
		return err
	}
	managed := filepath.Join(s.plan.RuntimeDir, "xray.json")
	if err := s.createManagedTun(); err != nil {
		return err
	}
	if err := s.renameTun(); err != nil {
		return err
	}
	if err := native.PrepareXRay(s.plan.ConfigPath, managed, "amn0", allowed); err != nil {
		return err
	}
	check := exec.Command(xray, "run", "-test", "-config", managed)
	check.Stdout, check.Stderr = os.Stderr, os.Stderr
	if err := check.Run(); err != nil {
		return fmt.Errorf("validate XRay configuration: %w", err)
	}
	if err := s.startBackend("XRAY_TUN_FD", xray, "run", "-config", managed); err != nil {
		return err
	}
	return configureTun("amn0", 1500, []netip.Prefix{
		netip.MustParsePrefix("10.255.255.1/30"),
		netip.MustParsePrefix("fd00:616d:6e::1/126"),
	}, allowed)
}

func (s *supervisor) startWireGuard(config native.WireGuard, allowed []netip.Prefix) error {
	backendName := "wireguard-go"
	if s.plan.Protocol == "amneziawg" {
		backendName = "amneziawg-go"
	}
	backend, err := RuntimeExecutable(backendName)
	if err != nil {
		return err
	}
	if err := s.createManagedTun(); err != nil {
		return err
	}
	if err := s.startBackend("WG_TUN_FD", backend, "--foreground", s.tunName); err != nil {
		return err
	}
	uapiPath := wireGuardUAPIPath(s.plan.Protocol, s.tunName)
	if err := waitPath(uapiPath, 5*time.Second); err != nil {
		return err
	}
	request, err := config.UAPI(allowed)
	if err != nil {
		return err
	}
	if err := sendUAPI(uapiPath, request); err != nil {
		return err
	}
	return configureTun(s.tunName, config.MTU, config.Addresses, allowed)
}

func configureTun(name string, mtu int, addresses, allowed []netip.Prefix) error {
	ip, err := trustedIP()
	if err != nil {
		return err
	}
	for _, address := range addresses {
		if err := runIP(ip, "address", "add", address.String(), "dev", name); err != nil {
			return err
		}
	}
	if err := runIP(ip, "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	for _, prefix := range allowed {
		args := []string{"route", "add", prefix.String(), "dev", name}
		if prefix.Addr().Is6() {
			args = append([]string{"-6"}, args...)
		}
		if err := runIP(ip, args...); err != nil {
			return err
		}
	}
	return nil
}

func (s *supervisor) setPlannedRoutes(allowed []netip.Prefix) error {
	s.state.Routes = make([]string, len(allowed))
	for i, prefix := range allowed {
		s.state.Routes[i] = prefix.String()
	}
	return WriteJSON(RecoveryPath, s.state, 0o600)
}

func (s *supervisor) createManagedTun() error {
	if s.tunFile != nil || s.tunName != "" {
		return errors.New("managed TUN was already created")
	}
	if len(s.plan.Owner) < 12 {
		return errors.New("invalid connection owner")
	}
	if _, err := net.InterfaceByName("amn0"); err == nil {
		return errors.New("interface amn0 appeared before managed TUN creation")
	}
	s.tunName = "amt" + s.plan.Owner[:12]
	file, iface, err := createTun(s.tunName)
	if err != nil {
		return err
	}
	s.tunFile = file
	s.tunIndex = iface.Index
	s.state.InterfaceIndex = iface.Index
	s.state.InterfaceName = s.tunName
	if err := WriteJSON(RecoveryPath, s.state, 0o600); err != nil {
		_ = file.Close()
		s.tunFile = nil
		return fmt.Errorf("record managed TUN identity: %w", err)
	}
	return nil
}

func (s *supervisor) renameTun() error {
	if s.tunName == "" || s.tunIndex == 0 {
		return errors.New("managed TUN identity is unavailable")
	}
	if iface, err := net.InterfaceByName(s.tunName); err != nil || iface.Index != s.tunIndex {
		return errors.New("managed staging TUN identity changed")
	}
	if _, err := net.InterfaceByName("amn0"); err == nil {
		return errors.New("foreign interface amn0 appeared during connection setup")
	}
	ip, err := trustedIP()
	if err != nil {
		return err
	}
	if err := runIP(ip, "link", "set", "dev", s.tunName, "name", "amn0"); err != nil {
		return err
	}
	iface, err := net.InterfaceByName("amn0")
	if err != nil || iface.Index != s.tunIndex {
		return errors.New("managed TUN identity changed after rename")
	}
	s.state.InterfaceName = "amn0"
	if err := WriteJSON(RecoveryPath, s.state, 0o600); err != nil {
		return fmt.Errorf("record managed TUN rename: %w", err)
	}
	return nil
}

func (s *supervisor) startBackend(tunEnvironment, path string, arguments ...string) error {
	logFile, err := os.OpenFile(filepath.Join(s.plan.RuntimeDir, "backend.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	command := exec.Command(path, arguments...)
	command.Stdout, command.Stderr = logFile, logFile
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	command.ExtraFiles = []*os.File{s.tunFile}
	command.Env = append(os.Environ(), tunEnvironment+"=3")
	if err := command.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start %s: %w", filepath.Base(path), err)
	}
	if err := s.tunFile.Close(); err != nil {
		_ = command.Process.Kill()
		logFile.Close()
		return fmt.Errorf("close supervisor TUN descriptor: %w", err)
	}
	s.tunFile = nil
	s.backend = command
	s.backendDone = make(chan error, 1)
	go func() {
		s.backendDone <- command.Wait()
		logFile.Close()
	}()
	backendStart, err := ProcessStart(command.Process.Pid)
	if err != nil {
		return fmt.Errorf("record backend identity: %w", err)
	}
	s.state.BackendPID = command.Process.Pid
	s.state.BackendStart = backendStart
	if err := WriteJSON(RecoveryPath, s.state, 0o600); err != nil {
		return fmt.Errorf("persist backend identity: %w", err)
	}
	return nil
}

func (s *supervisor) serve() error {
	requests := make(chan controlRequest)
	go func() {
		for {
			connection, err := s.listener.Accept()
			if err != nil {
				close(requests)
				return
			}
			line, _ := bufio.NewReader(connection).ReadString('\n')
			requests <- controlRequest{command: strings.TrimSpace(line), conn: connection}
		}
	}()

	var deadline <-chan time.Time
	var deadlineTimer *time.Timer
	defer func() {
		if deadlineTimer != nil {
			deadlineTimer.Stop()
		}
	}()
	callerCheck := time.NewTicker(250 * time.Millisecond)
	defer callerCheck.Stop()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	for {
		select {
		case request, ok := <-requests:
			if !ok {
				return errors.New("control socket closed")
			}
			switch request.command {
			case "status":
				fmt.Fprintln(request.conn, "ready")
			case "arm":
				if deadlineTimer != nil {
					fmt.Fprintln(request.conn, "error confirmation already armed")
					break
				}
				deadlineTimer = time.NewTimer(confirmationTimeout)
				deadline = deadlineTimer.C
				fmt.Fprintln(request.conn, "armed")
			case "confirm":
				if deadlineTimer == nil {
					fmt.Fprintln(request.conn, "error confirmation not armed")
					break
				}
				if !ProcessMatches(s.plan.CallerPID, s.plan.CallerStart) {
					fmt.Fprintln(request.conn, "error caller changed")
					request.conn.Close()
					return errors.New("connect caller changed before confirmation")
				}
				if err := WriteJSON(StatePath, s.state, 0o600); err != nil {
					fmt.Fprintln(request.conn, "error persist state")
					request.conn.Close()
					return err
				}
				s.confirmed = true
				if err := RemoveRecovery(s.plan.Owner); err != nil {
					fmt.Fprintln(request.conn, "error finalize recovery journal")
					request.conn.Close()
					return err
				}
				fmt.Fprintln(request.conn, "confirmed")
			case "stop":
				fmt.Fprintln(request.conn, "stopping")
				request.conn.Close()
				return nil
			default:
				fmt.Fprintln(request.conn, "error unknown command")
			}
			request.conn.Close()
		case <-deadline:
			if !s.confirmed {
				return errors.New("connection confirmation timed out")
			}
		case <-callerCheck.C:
			if !s.confirmed && !ProcessMatches(s.plan.CallerPID, s.plan.CallerStart) {
				return errors.New("connect caller exited before confirmation")
			}
		case err := <-s.backendDone:
			return fmt.Errorf("VPN backend exited: %w", err)
		case <-signals:
			return nil
		}
	}
}

func (s *supervisor) cleanup() {
	complete := true
	if s.tunFile != nil {
		if err := s.tunFile.Close(); err != nil {
			complete = false
		}
		s.tunFile = nil
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.backend != nil && s.backend.Process != nil {
		if s.state.InterfaceIndex != 0 && s.plan.Protocol != "xray" {
			if iface, err := net.InterfaceByName("amn0"); err == nil && iface.Index == s.state.InterfaceIndex {
				if ip, findErr := trustedIP(); findErr == nil {
					for i := len(s.state.Routes) - 1; i >= 0; i-- {
						prefix := netip.MustParsePrefix(s.state.Routes[i])
						args := []string{"route", "del", prefix.String(), "dev", "amn0"}
						if prefix.Addr().Is6() {
							args = append([]string{"-6"}, args...)
						}
						_ = runIP(ip, args...)
					}
				}
			}
		}
		pid := s.backend.Process.Pid
		if s.state.BackendStart == 0 || ProcessMatches(pid, s.state.BackendStart) {
			_ = s.backend.Process.Signal(syscall.SIGTERM)
			select {
			case <-s.backendDone:
			case <-time.After(3 * time.Second):
				if s.state.BackendStart == 0 || ProcessMatches(pid, s.state.BackendStart) {
					_ = s.backend.Process.Kill()
				}
				select {
				case <-s.backendDone:
				case <-time.After(2 * time.Second):
					complete = false
				}
			}
		}
		if s.state.BackendStart != 0 && ProcessMatches(pid, s.state.BackendStart) {
			complete = false
		}
	}
	if s.state.InterfaceIndex != 0 && InterfaceIndexExists(s.state.InterfaceIndex) {
		complete = false
	}
	if !complete {
		_ = WriteJSON(RecoveryPath, s.state, 0o600)
		return
	}
	var current State
	if ReadJSON(StatePath, &current) == nil && current.Owner == s.plan.Owner {
		if err := RemoveState(); err != nil {
			return
		}
	}
	if err := RemoveRecovery(s.plan.Owner); err != nil {
		return
	}
	_ = os.RemoveAll(s.plan.RuntimeDir)
}

func InterfaceIndexExists(index int) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return true
	}
	for _, iface := range interfaces {
		if iface.Index == index {
			return true
		}
	}
	return false
}

func RuntimeExecutable(name string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	base := filepath.Dir(executable)
	candidates := []string{
		filepath.Join(base, "libexec", "amn", name),
		filepath.Join(filepath.Dir(base), "libexec", "amn", name),
	}
	for _, candidate := range candidates {
		if trustedExecutable(candidate, false) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("trusted source-built %s is not installed beside amn", name)
}

func waitInterface(name string, timeout time.Duration) (*net.Interface, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		iface, err := net.InterfaceByName(name)
		if err == nil {
			return iface, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, fmt.Errorf("interface %s did not appear", name)
}

func wireGuardUAPIPath(protocol, interfaceName string) string {
	directory := "/var/run/wireguard"
	if protocol == "amneziawg" {
		directory = "/var/run/amneziawg"
	}
	return filepath.Join(directory, interfaceName+".sock")
}

func waitPath(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("runtime socket %s did not appear", path)
}

func sendUAPI(path, request string) error {
	connection, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return fmt.Errorf("open WireGuard UAPI: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write([]byte(request)); err != nil {
		return fmt.Errorf("configure WireGuard UAPI: %w", err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read WireGuard UAPI: %w", err)
	}
	if strings.TrimSpace(response) != "errno=0" {
		return fmt.Errorf("WireGuard UAPI rejected configuration: %s", strings.TrimSpace(response))
	}
	return nil
}

func trustedIP() (string, error) {
	for _, path := range []string{"/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"} {
		if trustedExecutable(path, true) {
			return path, nil
		}
	}
	return "", errors.New("trusted system ip utility is unavailable")
}

func trustedExecutable(path string, allowSymlink bool) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil || (!allowSymlink && canonical != absolute) {
		return false
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	for directory := filepath.Dir(canonical); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if directory == filepath.Dir(directory) {
			return true
		}
	}
}

func runIP(path string, arguments ...string) error {
	command := exec.Command(path, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func SendControl(ctx context.Context, socket, command string) (string, error) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintln(connection, command); err != nil {
		return "", err
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(response), err
}
