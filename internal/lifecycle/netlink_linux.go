package lifecycle

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var netlinkSequence atomic.Uint32

const bypassRouteProtocol = 186

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

func netlinkLookupBypassRoute(destination netip.Addr, priority uint32) (BypassRoute, error) {
	if !destination.IsValid() || !destination.Is4() || priority == 0 {
		return BypassRoute{}, fmt.Errorf("invalid IPv4 bypass destination")
	}
	message := syscall.RtMsg{Family: syscall.AF_INET, Dst_len: 32, Table: syscall.RT_TABLE_MAIN}
	address := destination.As4()
	responses, err := netlinkQuery(
		syscall.RTM_GETROUTE,
		syscall.NLM_F_REQUEST,
		structBytes(message),
		netlinkAttribute(syscall.RTA_DST, address[:]),
	)
	if err != nil {
		return BypassRoute{}, err
	}
	for _, response := range responses {
		if response.Header.Type != syscall.RTM_NEWROUTE || len(response.Data) < syscall.SizeofRtMsg {
			continue
		}
		var routeMessage syscall.RtMsg
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&routeMessage)), syscall.SizeofRtMsg), response.Data[:syscall.SizeofRtMsg])
		if routeMessage.Family != syscall.AF_INET || routeMessage.Type != syscall.RTN_UNICAST {
			continue
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&response)
		if err != nil {
			return BypassRoute{}, fmt.Errorf("parse route lookup attributes: %w", err)
		}
		result := BypassRoute{Destination: netip.PrefixFrom(destination, 32).String(), Priority: priority}
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case syscall.RTA_OIF:
				if len(attribute.Value) >= 4 {
					result.InterfaceIndex = int(nativeUint32(attribute.Value[:4]))
				}
			case syscall.RTA_GATEWAY:
				if len(attribute.Value) >= 4 {
					var gateway [4]byte
					copy(gateway[:], attribute.Value[:4])
					result.Gateway = netip.AddrFrom4(gateway).String()
				}
			}
		}
		if result.InterfaceIndex > 0 {
			return result, nil
		}
	}
	return BypassRoute{}, fmt.Errorf("no original IPv4 route to %s", destination)
}

func netlinkAddBypassRoute(route BypassRoute) error {
	return netlinkBypassRoute(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, route)
}

func netlinkDeleteBypassRoute(route BypassRoute) error {
	err := netlinkBypassRoute(syscall.RTM_DELROUTE, 0, route)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func netlinkBypassRouteExists(route BypassRoute) (bool, error) {
	destination, err := netip.ParsePrefix(route.Destination)
	if err != nil || !destination.Addr().Is4() || destination.Bits() != 32 {
		return false, fmt.Errorf("invalid IPv4 bypass route")
	}
	query := syscall.RtMsg{Family: syscall.AF_INET, Table: syscall.RT_TABLE_MAIN}
	responses, err := netlinkQuery(syscall.RTM_GETROUTE, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP, structBytes(query))
	if err != nil {
		return false, err
	}
	for _, response := range responses {
		if response.Header.Type != syscall.RTM_NEWROUTE || len(response.Data) < syscall.SizeofRtMsg {
			continue
		}
		var message syscall.RtMsg
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&message)), syscall.SizeofRtMsg), response.Data[:syscall.SizeofRtMsg])
		if message.Family != syscall.AF_INET || message.Table != syscall.RT_TABLE_MAIN || message.Protocol != bypassRouteProtocol || message.Dst_len != 32 {
			continue
		}
		attributes, parseErr := syscall.ParseNetlinkRouteAttr(&response)
		if parseErr != nil {
			return false, fmt.Errorf("parse bypass route attributes: %w", parseErr)
		}
		var foundDestination, foundGateway string
		var foundInterface int
		var foundPriority uint32
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case syscall.RTA_DST:
				if len(attribute.Value) >= 4 {
					var address [4]byte
					copy(address[:], attribute.Value[:4])
					foundDestination = netip.PrefixFrom(netip.AddrFrom4(address), 32).String()
				}
			case syscall.RTA_GATEWAY:
				if len(attribute.Value) >= 4 {
					var address [4]byte
					copy(address[:], attribute.Value[:4])
					foundGateway = netip.AddrFrom4(address).String()
				}
			case syscall.RTA_OIF:
				if len(attribute.Value) >= 4 {
					foundInterface = int(nativeUint32(attribute.Value[:4]))
				}
			case syscall.RTA_PRIORITY:
				if len(attribute.Value) >= 4 {
					foundPriority = nativeUint32(attribute.Value[:4])
				}
			}
		}
		if foundDestination == route.Destination && foundGateway == route.Gateway && foundInterface == route.InterfaceIndex && foundPriority == route.Priority {
			return true, nil
		}
	}
	return false, nil
}

func CleanupBypassRoutes(state State) error {
	for index := len(state.BypassRoutes) - 1; index >= 0; index-- {
		route := state.BypassRoutes[index]
		exists, err := netlinkBypassRouteExists(route)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if !route.Applied {
			return fmt.Errorf("unconfirmed bypass route %s exists; refusing unsafe cleanup", route.Destination)
		}
		if err := netlinkDeleteBypassRoute(route); err != nil {
			return fmt.Errorf("delete owned bypass route %s: %w", route.Destination, err)
		}
		exists, err = netlinkBypassRouteExists(route)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("owned bypass route %s remains", route.Destination)
		}
	}
	return nil
}

func netlinkBypassRoute(messageType uint16, flags uint16, route BypassRoute) error {
	destination, err := netip.ParsePrefix(route.Destination)
	if err != nil || !destination.IsValid() || !destination.Addr().Is4() || destination.Bits() != 32 || route.InterfaceIndex <= 0 || route.Priority == 0 {
		return fmt.Errorf("invalid IPv4 bypass route")
	}
	message := syscall.RtMsg{
		Family:   syscall.AF_INET,
		Dst_len:  32,
		Table:    syscall.RT_TABLE_MAIN,
		Protocol: bypassRouteProtocol,
		Scope:    syscall.RT_SCOPE_LINK,
		Type:     syscall.RTN_UNICAST,
	}
	address := destination.Addr().As4()
	attributes := [][]byte{
		netlinkAttribute(syscall.RTA_DST, address[:]),
		netlinkAttribute(syscall.RTA_OIF, structBytes(uint32(route.InterfaceIndex))),
		netlinkAttribute(syscall.RTA_PRIORITY, structBytes(route.Priority)),
	}
	if route.Gateway != "" {
		gateway, parseErr := netip.ParseAddr(route.Gateway)
		if parseErr != nil || !gateway.Is4() {
			return fmt.Errorf("invalid IPv4 bypass gateway")
		}
		gatewayBytes := gateway.As4()
		attributes = append(attributes, netlinkAttribute(syscall.RTA_GATEWAY, gatewayBytes[:]))
		message.Scope = syscall.RT_SCOPE_UNIVERSE
	}
	return netlinkRequest(
		messageType,
		syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|flags,
		structBytes(message),
		attributes...,
	)
}

func netlinkRequest(messageType uint16, flags uint16, payload []byte, attributes ...[]byte) error {
	responses, err := netlinkQuery(messageType, flags, payload, attributes...)
	if err != nil {
		return err
	}
	for _, message := range responses {
		if message.Header.Type == syscall.NLMSG_ERROR && len(message.Data) >= 4 && nativeInt32(message.Data[:4]) == 0 {
			return nil
		}
	}
	return fmt.Errorf("route netlink acknowledgement was not received")
}

func netlinkQuery(messageType uint16, flags uint16, payload []byte, attributes ...[]byte) ([]syscall.NetlinkMessage, error) {
	sequence := netlinkSequence.Add(1)
	length := syscall.NLMSG_HDRLEN + len(payload)
	for _, attribute := range attributes {
		length += len(attribute)
	}
	header := syscall.NlMsghdr{Len: uint32(length), Type: messageType, Flags: flags, Seq: sequence}
	request := make([]byte, 0, length)
	request = append(request, structBytes(header)...)
	request = append(request, payload...)
	for _, attribute := range attributes {
		request = append(request, attribute...)
	}

	socket, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open route netlink socket: %w", err)
	}
	defer syscall.Close(socket)
	if err := syscall.Bind(socket, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("bind route netlink socket: %w", err)
	}
	timeout := syscall.NsecToTimeval((3 * time.Second).Nanoseconds())
	if err := syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, fmt.Errorf("set route netlink timeout: %w", err)
	}
	if err := syscall.Sendto(socket, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("send route netlink request: %w", err)
	}

	var result []syscall.NetlinkMessage
	for {
		buffer, err := receiveNetlinkDatagram(socket)
		if err != nil {
			return nil, fmt.Errorf("receive route netlink response: %w", err)
		}
		messages, err := syscall.ParseNetlinkMessage(buffer)
		if err != nil {
			return nil, fmt.Errorf("parse route netlink response: %w", err)
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			if message.Header.Type == syscall.NLMSG_ERROR {
				if len(message.Data) < 4 {
					return nil, fmt.Errorf("short route netlink acknowledgement")
				}
				if code := nativeInt32(message.Data[:4]); code != 0 {
					return nil, fmt.Errorf("route netlink request: %w", syscall.Errno(-code))
				}
			}
			if message.Header.Type == syscall.NLMSG_DONE {
				return result, nil
			}
			result = append(result, message)
		}
		if flags&syscall.NLM_F_ROOT == 0 && len(result) > 0 {
			return result, nil
		}
	}
}

func receiveNetlinkDatagram(socket int) ([]byte, error) {
	probe := make([]byte, 1)
	count, _, flags, _, err := syscall.Recvmsg(socket, probe, nil, syscall.MSG_PEEK|syscall.MSG_TRUNC)
	if err != nil {
		return nil, err
	}
	if count <= 0 {
		return nil, fmt.Errorf("empty route netlink datagram")
	}
	const maximumNetlinkDatagram = 16 << 20
	if count > maximumNetlinkDatagram {
		return nil, fmt.Errorf("route netlink datagram is too large: %d bytes", count)
	}
	buffer := make([]byte, count)
	count, _, flags, _, err = syscall.Recvmsg(socket, buffer, nil, 0)
	if err != nil {
		return nil, err
	}
	if flags&syscall.MSG_TRUNC != 0 || count > len(buffer) {
		return nil, fmt.Errorf("truncated route netlink datagram")
	}
	return buffer[:count], nil
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

func nativeUint32(value []byte) uint32 {
	var result uint32
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&result)), 4), value)
	return result
}
