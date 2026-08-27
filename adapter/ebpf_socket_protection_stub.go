//go:build !with_ebpf || (!linux && !android)

package adapter

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

const EBPFSocketProtectionSupported = false

type EBPFSocketProtectionRegistration struct{}

func PrepareEBPFSocketProtection(context.Context) {
}

func EBPFSocketProtectionControl(context.Context) control.Func {
	return nil
}

func RegisterEBPFSocketProtection(_ context.Context, protectFunc control.Func) (*EBPFSocketProtectionRegistration, error) {
	if protectFunc == nil {
		return nil, E.New("socket protect function is nil")
	}
	return &EBPFSocketProtectionRegistration{}, nil
}

func ProtectEBPFSocket(control.Func, string, string, net.Conn) error {
	return nil
}

func (r *EBPFSocketProtectionRegistration) Close() {}
