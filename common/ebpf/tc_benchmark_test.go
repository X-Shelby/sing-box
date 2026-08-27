//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func BenchmarkMakeTCAssignmentKey(b *testing.B) {
	for _, test := range []struct {
		name        string
		source      netip.AddrPort
		destination netip.AddrPort
	}{
		{
			name:        "ipv4",
			source:      netip.MustParseAddrPort("192.0.2.10:53000"),
			destination: netip.MustParseAddrPort("203.0.113.10:443"),
		},
		{
			name:        "ipv6",
			source:      netip.MustParseAddrPort("[2001:db8::10]:53000"),
			destination: netip.MustParseAddrPort("[2001:db8:1::10]:443"),
		},
	} {
		b.Run(test.name, func(b *testing.B) {
			for range b.N {
				if _, err := makeTCAssignKey(ProtocolTCP, test.source, test.destination); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCompileUIDPolicy(b *testing.B) {
	policy := LocalPolicy{
		IncludeUIDConfigured: true,
		IncludeUID: []UIDRange{
			{Start: 10000, End: 199999},
			{Start: 300000, End: 399999},
		},
		ExcludeUID: []UIDRange{
			{Start: 12000, End: 12999},
			{Start: 350000, End: 350999},
		},
	}
	for range b.N {
		if _, _, err := compileUIDPolicy(policy); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileCIDRPolicy(b *testing.B) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	}
	for range b.N {
		if _, _, err := compileBypassCIDRPolicy(prefixes); err != nil {
			b.Fatal(err)
		}
	}
}
