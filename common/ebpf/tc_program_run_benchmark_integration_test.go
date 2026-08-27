//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func BenchmarkTCSharedIngressProgramRun(b *testing.B) {
	requireEBPFIntegration(b, "benchmark the unified TC packet program")
	backend, err := PrepareTC(TCConfig{
		ListenerPort:     65531,
		EnableIPv4:       true,
		EnableTCP:        true,
		SharedDNSMode:    DNSModeRespectPolicy,
		IncludeSourceMAC: []MACAddress{{0x02, 0, 0, 0, 0, 1}},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		b.Fatal(err)
	}
	packet := testIPv4TCPPacket(
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("203.0.113.10"),
		53000,
		443,
	)
	program := backend.runtime.programs[tcProgramSharedIngressEthernet]
	output := make([]byte, len(packet)+256)
	options := &CiliumEBPF.RunOptions{Data: packet, DataOut: output, Repeat: 1}
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for range b.N {
		if _, err = program.Run(options); err != nil {
			b.Fatal(err)
		}
	}
}
