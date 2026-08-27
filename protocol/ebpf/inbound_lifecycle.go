//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

func (i *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		return i.startSocketProtection()
	case adapter.StartStateStart:
	default:
		return nil
	}
	if err := i.startTCInbound(); err != nil {
		return combineStartError(err, i.cleanupStartFailure())
	}
	return nil
}

func (i *Inbound) startSocketProtection() error {
	if i.socketProtector == nil || i.socketProtectionRegistration != nil {
		return nil
	}
	registration, err := adapter.RegisterEBPFSocketProtection(i.ctx, i.socketProtector.ControlFunc())
	if err != nil {
		return E.Cause(err, "register eBPF socket protection")
	}
	i.socketProtectionRegistration = registration
	return nil
}

func (i *Inbound) startTCInbound() error {
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	defaultInterface := i.currentDefaultInterfaceName()
	localInterface := ""
	if i.localEnabled {
		localInterface = defaultInterface
		if localInterface == "" {
			i.logger.Warn("default interface unavailable; local TC eBPF interception is paused")
		}
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	if err := i.startTCListeners(); err != nil {
		return err
	}
	backend, err := commonEBPF.PrepareTC(commonEBPF.TCConfig{
		ListenerPort:        i.listeners.selectedPort(),
		EnableIPv4:          true,
		EnableLocalIPv6:     i.localIPv6,
		EnableSharedIPv6:    i.sharedIPv6,
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		LocalPolicy:         i.localPolicy,
		SharedDNSMode:       toCommonDNSMode(i.sharedDNSMode),
		SharedBypassPrivate: i.sharedBypassPrivate,
		FakeIPIPv4:          i.fakeIPIPv4Prefix,
		FakeIPIPv6:          i.fakeIPIPv6Prefix,
		IncludeSourceCIDR:   i.sharedOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:   i.sharedOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:    i.sharedIncludeMAC,
		ExcludeSourceMAC:    i.sharedExcludeMAC,
	})
	if err != nil {
		return err
	}
	if i.socketProtector != nil {
		if err = i.socketProtector.Attach(backend); err != nil {
			return E.Errors(err, backend.Close())
		}
	}
	if err = i.listeners.registerTCTCPListeners(backend); err != nil {
		return E.Errors(err, backend.Close())
	}
	dataPlane, err := startTCDataPlane(
		backend,
		i.localEnabled,
		i.localIPv6 || i.sharedIPv6,
		localInterface,
		sharedInterfaces,
		i.hostAddresses(),
		len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
		i.tcPriority,
	)
	if err != nil {
		return err
	}
	i.setTCDataPlane(dataPlane)
	if err = i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if err = backend.Enable(); err != nil {
		return err
	}
	if err = i.startTCInterfaceMonitor(); err != nil {
		return err
	}
	network := "tcp"
	if i.enableTCP && i.enableUDP {
		network = "tcp,udp"
	} else if i.enableUDP {
		network = "udp"
	}
	i.logger.Debug(
		"eBPF TC active: mode=", i.mode,
		", network=", network,
		", local_ipv6=", i.localIPv6,
		", shared_ipv6=", i.sharedIPv6,
		", default_interface=", defaultInterface,
		", local_interface=", localInterface,
		", shared_interfaces=[", strings.Join(i.sharedOptions.Interface, ", "), "]",
		", attachments=[", strings.Join(dataPlane.attachmentDescriptions(), ", "), "]",
		", listeners=[", i.listeners.String(), "]",
		", delivery_interface=", dataPlane.deliveryName(),
		", routing_mark=0x", strconv.FormatUint(uint64(commonEBPF.TCRoutingMark), 16),
		", routing_table=", tcPolicyRoutingTable,
		", tc_priority=", i.tcPriority,
	)
	return nil
}

func combineStartError(startErr error, cleanupErr error) error {
	if cleanupErr == nil {
		return startErr
	}
	return E.Errors(startErr, E.Cause(cleanupErr, "cleanup eBPF inbound"))
}

func (i *Inbound) Close() error {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	return i.closeResources()
}

func (i *Inbound) cleanupStartFailure() error {
	return i.closeResources()
}

func (i *Inbound) closeResources() error {
	monitorErr := i.stopTCInterfaceMonitor()
	i.stopBypassRuleSets()
	dataPlane := i.takeTCDataPlane()
	disableErr := dataPlane.disable()
	listenerErr := i.closeListeners()
	i.udpNat.Purge()
	i.closeSocketProtection()
	return E.Errors(monitorErr, disableErr, listenerErr, dataPlane.Close())
}

func (i *Inbound) closeSocketProtection() {
	if i.socketProtectionRegistration != nil {
		i.socketProtectionRegistration.Close()
		i.socketProtectionRegistration = nil
	}
	if i.socketProtector != nil {
		i.socketProtector.Close()
	}
}

func (i *Inbound) tcBackend() *commonEBPF.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.backend
}

func (i *Inbound) setTCDataPlane(dataPlane *tcDataPlane) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() *tcDataPlane {
	i.tcDataPlaneAccess.Lock()
	dataPlane := i.tcDataPlane
	i.tcDataPlane = nil
	i.tcDataPlaneAccess.Unlock()
	return dataPlane
}

func (i *Inbound) reconcileTCDataPlane(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.reconcile(localInterface, sharedInterfaces, hostAddresses)
}
