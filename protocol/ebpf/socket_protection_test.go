//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"testing"
)

func TestSocketProtectorCollectsCookieBeforeAttach(t *testing.T) {
	protector := newSocketProtector()
	listener, err := (&net.ListenConfig{Control: protector.ControlFunc()}).Listen(
		context.Background(),
		"tcp4",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	protector.access.Lock()
	pending := len(protector.pending)
	protector.access.Unlock()
	if pending != 1 {
		t.Fatalf("unexpected pending socket cookie count: %d", pending)
	}
	protector.Close()
	if err = protector.protectCookie(1); err != nil {
		t.Fatal(err)
	}
}
