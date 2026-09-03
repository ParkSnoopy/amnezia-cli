package routes

import (
	"fmt"
	"net/netip"
	"sort"
)

// Complement returns every IPv4 address not covered by exclusions.
func Complement(exclusions []netip.Prefix) ([]netip.Prefix, error) {
	result := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, exclusion := range exclusions {
		if !exclusion.IsValid() {
			return nil, fmt.Errorf("invalid exclusion")
		}
		if !exclusion.Addr().Is4() {
			return nil, fmt.Errorf("IPv6 exclusions are not supported")
		}
		exclusion = exclusion.Masked()
		result = subtractAll(result, exclusion)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Addr().Compare(b.Addr()) != 0 {
			return a.Addr().Compare(b.Addr()) < 0
		}
		return a.Bits() < b.Bits()
	})
	return result, nil
}

func Parse(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("CIDR %q has host bits set", value)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("CIDR %q is IPv6; IPv6 is not supported", value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func subtractAll(source []netip.Prefix, exclusion netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(source))
	for _, prefix := range source {
		result = append(result, subtract(prefix, exclusion)...)
	}
	return result
}

func subtract(prefix, exclusion netip.Prefix) []netip.Prefix {
	if exclusion.Bits() <= prefix.Bits() && exclusion.Contains(prefix.Addr()) {
		return nil
	}
	if !prefix.Contains(exclusion.Addr()) {
		return []netip.Prefix{prefix}
	}
	left, right := split(prefix)
	result := subtract(left, exclusion)
	return append(result, subtract(right, exclusion)...)
}

func split(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	left := netip.PrefixFrom(prefix.Addr(), bits)
	byteIndex := prefix.Bits() / 8
	bitIndex := uint(7 - prefix.Bits()%8)
	bytes := prefix.Addr().As4()
	bytes[byteIndex] |= 1 << bitIndex
	return left, netip.PrefixFrom(netip.AddrFrom4(bytes), bits)
}
