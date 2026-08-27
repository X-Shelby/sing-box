//go:build with_ebpf && (linux || android)

package adapter

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing/service"
)

func TestEBPFSocketProtectionRegistration(t *testing.T) {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	if protectFunc := EBPFSocketProtectionControl(ctx); protectFunc != nil {
		t.Fatal("socket protection enabled before preparation")
	}
	if _, err := RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("registered socket protection before preparation")
	}
	PrepareEBPFSocketProtection(ctx)
	dynamicProtect := EBPFSocketProtectionControl(ctx)
	if dynamicProtect == nil {
		t.Fatal("socket protection was not prepared")
	}
	if err := dynamicProtect("tcp", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Uint32
	registration, err := RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error {
		calls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registration.Close)
	if _, err = RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error { return nil }); err == nil {
		t.Fatal("accepted a second socket protect registration")
	}
	if err = dynamicProtect("udp", "1.1.1.1:53", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected protect call count: %d", calls.Load())
	}
	registration.Close()
	if err = dynamicProtect("tcp", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("closed registration was still active: %d", calls.Load())
	}

	secondCalls := new(atomic.Uint32)
	secondRegistration, err := RegisterEBPFSocketProtection(ctx, func(string, string, syscall.RawConn) error {
		secondCalls.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondRegistration.Close)
	if err = dynamicProtect("tcp", "example.com:443", nil); err != nil {
		t.Fatal(err)
	}
	if secondCalls.Load() != 1 {
		t.Fatalf("captured control did not follow new registration: %d", secondCalls.Load())
	}
}

func TestEBPFSocketProtectionContextIsolation(t *testing.T) {
	firstContext := service.ContextWithDefaultRegistry(context.Background())
	secondContext := service.ContextWithDefaultRegistry(context.Background())
	PrepareEBPFSocketProtection(firstContext)
	PrepareEBPFSocketProtection(secondContext)
	firstRegistration, err := RegisterEBPFSocketProtection(firstContext, func(string, string, syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer firstRegistration.Close()
	secondRegistration, err := RegisterEBPFSocketProtection(secondContext, func(string, string, syscall.RawConn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	secondRegistration.Close()
}
