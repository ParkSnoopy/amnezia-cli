package lifecycle

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
)

type ifreqFlags struct {
	Name  [16]byte
	Flags uint16
	Pad   [22]byte
}

func createTun(name string) (*os.File, *net.Interface, error) {
	if len(name) == 0 || len(name) >= 16 {
		return nil, nil, fmt.Errorf("invalid TUN name %q", name)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	request := ifreqFlags{Flags: iffTun | iffNoPI}
	copy(request.Name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		file.Close()
		return nil, nil, fmt.Errorf("create TUN %s: %w", name, errno)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect created TUN %s: %w", name, err)
	}
	return file, iface, nil
}
