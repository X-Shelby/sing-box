//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func BenchmarkUDPDirectStateLookup(b *testing.B) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("203.0.113.10:443")
	table.setDirectBinding(client, destination, nil)
	state, _ := table.load(client)
	b.ResetTimer()
	for range b.N {
		loadedState, loaded := table.load(client)
		if !loaded || loadedState != state {
			b.Fatal("UDP client state disappeared")
		}
		if _, loaded = loadedState.redirectBinding(destination); !loaded {
			b.Fatal("UDP destination binding disappeared")
		}
	}
}

func BenchmarkUDPReplyAliasInstall(b *testing.B) {
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	base := netip.MustParseAddrPort("203.0.113.10:443")
	reply := netip.MustParseAddrPort("203.0.113.11:443")
	for range b.N {
		var table udpClientTable
		table.setDirectBinding(client, base, nil)
		state, _ := table.load(client)
		if !table.setDirectReplyBinding(client, state, reply) {
			b.Fatal("failed to install UDP reply alias")
		}
	}
}
