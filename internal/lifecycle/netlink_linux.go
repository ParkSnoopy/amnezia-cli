package lifecycle

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var netlinkSequence atomic.Uint32

func netlinkRename(index int, name string) error {
	if index <= 0 || name == "" || len(name) >= 16 {
		return fmt.Errorf("invalid link rename")
	}
	message := syscall.IfInfomsg{Family: syscall.AF_UNSPEC, Index: int32(index)}
	return netlinkRequest(
		syscall.RTM_NEWLINK,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,
		structBytes(message),
		netlinkAttribute(syscall.IFLA_IFNAME, append([]byte(name), 0)),
	)
}

func netlinkConfigure(index, mtu int) error {
	if index <= 0 || mtu <= 0 {
		return fmt.Errorf("invalid link configuration")
	}
	message := syscall.IfInfomsg{
		Family: syscall.AF_UNSPEC,
		Index:  int32(index),
		Flags:  syscall.IFF_UP,
		Change: syscall.IFF_UP,
	}
	return netlinkRequest(
		syscall.RTM_NEWLINK,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK,
		structBytes(message),
		netlinkAttribute(syscall.IFLA_MTU, structBytes(uint32(mtu))),
	)
}

func netlinkAddAddress(index int, prefix netip.Prefix) error {
	if index <= 0 || !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 interface address")
	}
	address := prefix.Addr().As4()
	message := syscall.IfAddrmsg{
		Family:    syscall.AF_INET,
		Prefixlen: uint8(prefix.Bits()),
		Scope:     syscall.RT_SCOPE_UNIVERSE,
		Index:     uint32(index),
	}
	return netlinkRequest(
		syscall.RTM_NEWADDR,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL,
		structBytes(message),
		netlinkAttribute(syscall.IFA_LOCAL, address[:]),
		netlinkAttribute(syscall.IFA_ADDRESS, address[:]),
	)
}

func netlinkAddRoute(index int, prefix netip.Prefix) error {
	return netlinkRoute(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, index, prefix)
}

func netlinkDeleteRoute(index int, prefix netip.Prefix) error {
	return netlinkRoute(syscall.RTM_DELROUTE, 0, index, prefix)
}

func netlinkRoute(messageType uint16, flags uint16, index int, prefix netip.Prefix) error {
	if index <= 0 || !prefix.IsValid() || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid IPv4 route")
	}
	message := syscall.RtMsg{
		Family:   syscall.AF_INET,
		Dst_len:  uint8(prefix.Bits()),
		Table:    syscall.RT_TABLE_MAIN,
		Protocol: syscall.RTPROT_BOOT,
		Scope:    syscall.RT_SCOPE_LINK,
		Type:     syscall.RTN_UNICAST,
	}
	attributes := [][]byte{netlinkAttribute(syscall.RTA_OIF, structBytes(uint32(index)))}
	if prefix.Bits() != 0 {
		address := prefix.Addr().As4()
		attributes = append(attributes, netlinkAttribute(syscall.RTA_DST, address[:]))
	}
	return netlinkRequest(
		messageType,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags,
		structBytes(message),
		attributes...,
	)
}

func netlinkRequest(messageType uint16, flags uint16, payload []byte, attributes ...[]byte) error {
	sequence := netlinkSequence.Add(1)
	length := syscall.NLMSG_HDRLEN + len(payload)
	for _, attribute := range attributes {
		length += len(attribute)
	}
	header := syscall.NlMsghdr{
		Len:   uint32(length),
		Type:  messageType,
		Flags: flags,
		Seq:   sequence,
	}
	request := make([]byte, 0, length)
	request = append(request, structBytes(header)...)
	request = append(request, payload...)
	for _, attribute := range attributes {
		request = append(request, attribute...)
	}

	socket, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open route netlink socket: %w", err)
	}
	defer syscall.Close(socket)
	if err := syscall.Bind(socket, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind route netlink socket: %w", err)
	}
	timeout := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return fmt.Errorf("set route netlink timeout: %w", err)
	}
	if err := syscall.Sendto(socket, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("send route netlink request: %w", err)
	}

	buffer := make([]byte, 8192)
	for {
		count, _, err := syscall.Recvfrom(socket, buffer, 0)
		if err != nil {
			return fmt.Errorf("receive route netlink response: %w", err)
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:count])
		if err != nil {
			return fmt.Errorf("parse route netlink response: %w", err)
		}
		for _, message := range messages {
			if message.Header.Seq != sequence || message.Header.Type != syscall.NLMSG_ERROR {
				continue
			}
			if len(message.Data) < 4 {
				return fmt.Errorf("short route netlink acknowledgement")
			}
			code := nativeInt32(message.Data[:4])
			if code == 0 {
				return nil
			}
			return fmt.Errorf("route netlink request: %w", syscall.Errno(-code))
		}
	}
}

func netlinkAttribute(kind uint16, data []byte) []byte {
	length := syscall.SizeofRtAttr + len(data)
	attribute := make([]byte, netlinkAlign(length))
	header := syscall.RtAttr{Len: uint16(length), Type: kind}
	copy(attribute, structBytes(header))
	copy(attribute[syscall.SizeofRtAttr:], data)
	return attribute
}

func netlinkAlign(length int) int {
	return (length + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func structBytes[T any](value T) []byte {
	size := int(unsafe.Sizeof(value))
	result := make([]byte, size)
	copy(result, unsafe.Slice((*byte)(unsafe.Pointer(&value)), size))
	return result
}

func nativeInt32(value []byte) int32 {
	var result int32
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&result)), 4), value)
	return result
}
