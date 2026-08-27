//go:build with_ebpf && (linux || android)

package adapter

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

const EBPFSocketProtectionSupported = true

type EBPFSocketProtectionRegistration struct {
	protectFunc control.Func
	service     *ebpfSocketProtectionService
}

type ebpfSocketProtectionService struct {
	registration atomic.Pointer[EBPFSocketProtectionRegistration]
	control      control.Func
}

func PrepareEBPFSocketProtection(ctx context.Context) {
	if service.FromContext[*ebpfSocketProtectionService](ctx) != nil {
		return
	}
	protectService := new(ebpfSocketProtectionService)
	protectService.control = func(network string, address string, conn syscall.RawConn) error {
		registration := protectService.registration.Load()
		if registration == nil {
			return nil
		}
		return registration.protectFunc(network, address, conn)
	}
	service.MustRegister[*ebpfSocketProtectionService](ctx, protectService)
}

func EBPFSocketProtectionControl(ctx context.Context) control.Func {
	protectService := service.FromContext[*ebpfSocketProtectionService](ctx)
	if protectService == nil {
		return nil
	}
	return protectService.control
}

func RegisterEBPFSocketProtection(ctx context.Context, protectFunc control.Func) (*EBPFSocketProtectionRegistration, error) {
	if protectFunc == nil {
		return nil, E.New("socket protect function is nil")
	}
	protectService := service.FromContext[*ebpfSocketProtectionService](ctx)
	if protectService == nil {
		return nil, E.New("socket protection service is not prepared")
	}
	registration := &EBPFSocketProtectionRegistration{protectFunc: protectFunc, service: protectService}
	if !protectService.registration.CompareAndSwap(nil, registration) {
		return nil, E.New("a socket protect function is already registered")
	}
	return registration, nil
}

func ProtectEBPFSocket(protectFunc control.Func, network string, address string, conn net.Conn) error {
	if protectFunc == nil {
		return nil
	}
	syscallConn, loaded := conn.(syscall.Conn)
	if !loaded {
		return E.New("socket does not expose syscall connection")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return E.Cause(err, "access socket syscall connection")
	}
	return protectFunc(network, address, rawConn)
}

func (r *EBPFSocketProtectionRegistration) Close() {
	if r == nil {
		return
	}
	r.service.registration.CompareAndSwap(r, nil)
}
