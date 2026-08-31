package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	configurationLimit = 16 * 1024 * 1024
	xrayTrafficMark    = 0x82
)

func configureUplink(uplink string) error {
	return internet.RegisterDialerController(func(_ string, _ string, connection syscall.RawConn) error {
		var socketError error
		if err := connection.Control(func(fileDescriptor uintptr) {
			if err := syscall.SetsockoptString(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, uplink); err != nil {
				socketError = fmt.Errorf("bind XRay socket to uplink: %w", err)
				return
			}
			if err := syscall.SetsockoptInt(int(fileDescriptor), syscall.SOL_SOCKET, syscall.SO_MARK, xrayTrafficMark); err != nil {
				socketError = fmt.Errorf("mark XRay socket: %w", err)
			}
		}); err != nil {
			return fmt.Errorf("control XRay socket: %w", err)
		}
		return socketError
	})
}

func run(arguments []string) error {
	if len(arguments) == 2 && arguments[1] == "--check" {
		return nil
	}
	if len(arguments) != 8 {
		return fmt.Errorf("internal XRay runner expects configuration, tun2socks, interface, endpoint, gateway, uplink, and error status")
	}

	configuration, err := os.ReadFile(arguments[1])
	if err != nil {
		return fmt.Errorf("cannot read staged XRay configuration")
	}
	if len(configuration) == 0 || len(configuration) > configurationLimit {
		return fmt.Errorf("staged XRay configuration has an invalid size")
	}
	if err := configureUplink(arguments[6]); err != nil {
		return err
	}
	coreConfiguration, err := core.LoadConfig("json", bytes.NewReader(configuration))
	if err != nil {
		return fmt.Errorf("XRay configuration failed: %w", err)
	}
	server, err := core.New(coreConfiguration)
	if err != nil {
		return fmt.Errorf("XRay configuration failed: %w", err)
	}
	if err := server.Start(); err != nil {
		return fmt.Errorf("XRay start failed: %w", err)
	}

	device := "tun://" + arguments[3]
	worker := exec.Command(arguments[2], "-device", device, "-proxy", "socks5://127.0.0.1:10808")
	worker.Stdin = nil
	worker.Stdout = os.Stdout
	worker.Stderr = os.Stderr
	if err := worker.Start(); err != nil {
		_ = server.Close()
		return fmt.Errorf("cannot start tun2socks")
	}

	workerResult := make(chan error, 1)
	go func() {
		workerResult <- worker.Wait()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var workerError error
	select {
	case received := <-signals:
		_ = worker.Process.Signal(received)
		<-workerResult
		workerError = nil
	case workerError = <-workerResult:
		if workerError == nil {
			workerError = fmt.Errorf("tun2socks exited before stop")
		} else {
			workerError = fmt.Errorf("tun2socks exited unsuccessfully: %w", workerError)
		}
	}
	signal.Stop(signals)
	if err := server.Close(); err != nil {
		return fmt.Errorf("XRay stop failed: %w", err)
	}
	return workerError
}

func errorCategory(err error) string {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "XRay configuration failed:"):
		return "configuration"
	case strings.HasPrefix(message, "XRay start failed:"):
		return "xray-start"
	case message == "cannot start tun2socks":
		return "tun2socks-start"
	case strings.HasPrefix(message, "tun2socks exited"):
		return "tun2socks-exit"
	default:
		return "runner"
	}
}

func main() {
	if err := run(os.Args); err != nil {
		if len(os.Args) == 8 {
			_ = os.WriteFile(os.Args[7], []byte(errorCategory(err)), 0600)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
