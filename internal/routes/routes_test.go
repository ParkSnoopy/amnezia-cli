package routes

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestComplementDocumentedIPv4Example(t *testing.T) {
	excluded := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	got, err := Complement(excluded)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/9", "192.128.0.0/11",
		"192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14",
		"192.176.0.0/12", "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7",
		"196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4", "224.0.0.0/3",
	}
	actual := make([]string, len(got))
	for i, prefix := range got {
		actual[i] = prefix.String()
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("unexpected complement:\n got %v\nwant %v", actual, want)
	}
}

func TestComplementFullIPv4Exclusion(t *testing.T) {
	got, err := Complement([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty complement, got %v", got)
	}
}

func TestComplementHandlesOverlapAndDuplicates(t *testing.T) {
	excluded := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	got, err := Complement(excluded)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range got {
		if prefix.Contains(netip.MustParseAddr("10.1.2.3")) {
			t.Fatalf("excluded address remained in %s", prefix)
		}
	}
}

func TestParseRejectsHostBits(t *testing.T) {
	if _, err := Parse([]string{"192.168.1.1/24"}); err == nil {
		t.Fatal("expected host-bit error")
	}
}

func TestParseRejectsIPv6(t *testing.T) {
	if _, err := Parse([]string{"2001:db8::/32"}); err == nil {
		t.Fatal("expected IPv6 rejection")
	}
}
