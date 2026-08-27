//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func TestUDPDirectBinding(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	sourceMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	table.setDirectBinding(client, destination, sourceMAC)
	state, loaded := table.load(client)
	if !loaded {
		t.Fatal("client state was not created")
	}
	if _, loaded := state.redirectBinding(destination); !loaded {
		t.Fatal("direct binding was not installed")
	}
	if actual := state.sourceMACAddress(); !bytes.Equal(actual, sourceMAC) {
		t.Fatalf("unexpected source MAC: %s", actual)
	}
}

func TestUDPReplySocketLifecycle(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	destination := netip.MustParseAddrPort("1.1.1.1:53")
	table.setDirectBinding(client, destination, nil)
	state, _ := table.load(client)
	created := 0
	create := func(netip.AddrPort) (*net.UDPConn, error) {
		created++
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	first, err := state.replySocket(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	second, err := state.replySocket(destination, create)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || created != 1 {
		t.Fatalf("reply socket was not reused: first=%p second=%p created=%d", first, second, created)
	}
	table.delete(client, state)
	if _, err = state.replySocket(destination, create); err == nil {
		t.Fatal("closed UDP session accepted a reply socket")
	}
	if _, err = first.WriteToUDPAddrPort([]byte{1}, netip.MustParseAddrPort("127.0.0.1:9")); err == nil {
		t.Fatal("UDP reply socket remained open after session deletion")
	}
}

func TestUDPDirectReplyBindingChecksGeneration(t *testing.T) {
	var table udpClientTable
	client := netip.MustParseAddrPort("192.0.2.10:53000")
	base := netip.MustParseAddrPort("1.1.1.1:53")
	reply := netip.MustParseAddrPort("8.8.8.8:53")
	table.setDirectBinding(client, base, nil)
	state, _ := table.load(client)
	if !table.setDirectReplyBinding(client, state, reply) {
		t.Fatal("reply binding was not installed")
	}
	if binding, loaded := state.redirectBinding(reply); !loaded || !binding.replyAlias {
		t.Fatalf("unexpected reply binding: %+v", binding)
	}
	table.delete(client, state)
	if table.setDirectReplyBinding(client, state, netip.MustParseAddrPort("9.9.9.9:53")) {
		t.Fatal("closed session was resurrected")
	}
}
