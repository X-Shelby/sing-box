//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64
)

type udpClientTable struct {
	clientShards [udpClientShardCount]udpClientShard
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*udpClientState
}

type udpClientState struct {
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	bindings        map[netip.AddrPort]udpRedirectBinding
	replySockets    map[netip.AddrPort]*net.UDPConn
	replyAliasCount uint16
	closed          bool
}

type udpRedirectBinding struct {
	replyAlias bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	state, loaded := shard.clients[client]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if state, loaded := t.load(client); loaded {
		return state
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[client]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[netip.AddrPort]*udpClientState)
	}
	state := &udpClientState{bindings: make(map[netip.AddrPort]udpRedirectBinding)}
	shard.clients[client] = state
	return state
}

func (t *udpClientTable) clientShard(client netip.AddrPort) *udpClientShard {
	port := client.Port()
	return &t.clientShards[(port^port>>8)&(udpClientShardCount-1)]
}

func (t *udpClientTable) setDirectBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
) {
	state := t.loadOrCreate(client)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.bindings[destination] = udpRedirectBinding{}
}

func (t *udpClientTable) setDirectReplyBinding(
	client netip.AddrPort,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expected {
		return
	}
	delete(shard.clients, client)
	expected.access.Lock()
	expected.closed = true
	for destination, socket := range expected.replySockets {
		_ = socket.Close()
		delete(expected.replySockets, destination)
	}
	clear(expected.bindings)
	expected.replyAliasCount = 0
	expected.access.Unlock()
}

func (s *udpClientState) replySocket(
	source netip.AddrPort,
	create func(netip.AddrPort) (*net.UDPConn, error),
) (*net.UDPConn, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	if socket := s.replySockets[source]; socket != nil {
		return socket, nil
	}
	socket, err := create(source)
	if err != nil {
		return nil, err
	}
	if s.replySockets == nil {
		s.replySockets = make(map[netip.AddrPort]*net.UDPConn)
	}
	s.replySockets[source] = socket
	return socket, nil
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}
