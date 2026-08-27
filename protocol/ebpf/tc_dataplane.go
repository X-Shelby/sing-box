//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	tcLocalFilterHandle    = 0x5344
	tcSharedFilterHandle   = 0x5345
	tcDeliveryFilterHandle = 0x5346
)

var tcVethSequence atomic.Uint32

type tcInterfaceRole struct {
	local  bool
	shared bool
}

type tcInterfaceAttachment struct {
	interfaceName  string
	interfaceIndex int
	framing        commonEBPF.TCLinkFraming
	role           tcInterfaceRole
	lock           io.Closer
	localFilter    *netlink.BpfFilter
	sharedFilter   *netlink.BpfFilter
}

type tcDeliveryLink struct {
	redirectName string
	deliveryName string
	redirect     netlink.Link
	delivery     netlink.Link
	filter       *netlink.BpfFilter
	sysctls      []tcSysctlState
}

type tcSysctlState struct {
	path     string
	original string
}

type tcDataPlane struct {
	access                sync.Mutex
	backend               *commonEBPF.TCBackend
	routing               *tcPolicyRouting
	delivery              *tcDeliveryLink
	attachments           []*tcInterfaceAttachment
	localInterface        string
	sharedInterfaces      []string
	hostAddresses         []netip.Addr
	sharedSourceMACPolicy bool
	priority              uint16
}

func startTCDataPlane(
	backend *commonEBPF.TCBackend,
	localEnabled bool,
	enableIPv6 bool,
	localInterface string,
	sharedInterfaces []string,
	hostAddresses []netip.Addr,
	sharedSourceMACPolicy bool,
	priority uint16,
) (*tcDataPlane, error) {
	dataPlane := &tcDataPlane{backend: backend, sharedSourceMACPolicy: sharedSourceMACPolicy, priority: priority}
	cleanup := func(startErr error) (*tcDataPlane, error) {
		return nil, E.Errors(startErr, dataPlane.Close())
	}
	routing, err := startTCPolicyRouting(enableIPv6)
	if err != nil {
		return cleanup(err)
	}
	dataPlane.routing = routing
	if localEnabled {
		delivery, err := createTCDeliveryLink(backend, priority)
		if err != nil {
			return cleanup(err)
		}
		dataPlane.delivery = delivery
	}
	attachments, err := attachTCInterfaces(backend, localInterface, sharedInterfaces, sharedSourceMACPolicy, priority)
	if err != nil {
		return cleanup(err)
	}
	dataPlane.attachments = attachments
	dataPlane.localInterface = localInterface
	dataPlane.sharedInterfaces = slices.Clone(sharedInterfaces)
	if err = backend.UpdateHostAddresses(hostAddresses); err != nil {
		return cleanup(err)
	}
	dataPlane.hostAddresses = slices.Clone(hostAddresses)
	return dataPlane, nil
}

func attachTCInterfaces(
	backend *commonEBPF.TCBackend,
	localInterface string,
	sharedInterfaces []string,
	sharedSourceMACPolicy bool,
	priority uint16,
) ([]*tcInterfaceAttachment, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	attachments := make([]*tcInterfaceAttachment, 0, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	for interfaceName, role := range roles {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil && role.shared && !role.local && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		attachment, err := attachTCInterface(link, backend, role, sharedSourceMACPolicy, priority)
		if err != nil {
			for index := len(attachments) - 1; index >= 0; index-- {
				_ = attachments[index].Close()
			}
			return nil, E.Cause(err, "attach TC eBPF interface ", interfaceName)
		}
		attachments = append(attachments, attachment)
	}
	return attachments, nil
}

func (d *tcDataPlane) deliveryName() string {
	if d == nil || d.delivery == nil {
		return ""
	}
	return d.delivery.deliveryName
}

func (d *tcDataPlane) reconcile(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return E.New("TC eBPF data plane is closed")
	}
	if err := d.backend.Disable(); err != nil {
		return err
	}
	oldLocal := d.localInterface
	oldShared := slices.Clone(d.sharedInterfaces)
	oldHostAddresses := slices.Clone(d.hostAddresses)
	if err := closeTCInterfaceAttachments(d.attachments); err != nil {
		restoreErr := d.restoreState(oldLocal, oldShared, oldHostAddresses)
		return E.Errors(E.Cause(err, "detach stale TC eBPF interface"), restoreErr)
	}
	d.attachments = nil
	attachments, err := attachTCInterfaces(
		d.backend,
		localInterface,
		sharedInterfaces,
		d.sharedSourceMACPolicy,
		d.priority,
	)
	if err != nil {
		return E.Errors(err, d.restoreState(oldLocal, oldShared, oldHostAddresses))
	}
	d.attachments = attachments
	if err = d.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return E.Errors(err, d.restoreState(oldLocal, oldShared, oldHostAddresses))
	}
	d.localInterface = localInterface
	d.sharedInterfaces = slices.Clone(sharedInterfaces)
	d.hostAddresses = slices.Clone(hostAddresses)
	if err = d.backend.Enable(); err != nil {
		_ = d.backend.Disable()
		return E.Errors(err, d.restoreState(oldLocal, oldShared, oldHostAddresses))
	}
	return nil
}

func (a *tcInterfaceAttachment) filtersAttached(priority uint16) (bool, error) {
	link, err := netlink.LinkByName(a.interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if link.Attrs().Index != a.interfaceIndex {
		return false, nil
	}
	if a.role.local {
		attached, err := tcFilterAttached(
			link,
			netlink.HANDLE_MIN_EGRESS,
			"sb_tc_local",
			tcLocalFilterHandle,
			priority,
		)
		if err != nil || !attached {
			return attached, err
		}
	}
	if a.role.shared {
		attached, err := tcFilterAttached(
			link,
			netlink.HANDLE_MIN_INGRESS,
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil || !attached {
			return attached, err
		}
	}
	return true, nil
}

func (d *tcDataPlane) updateHostAddresses(hostAddresses []netip.Addr) error {
	d.access.Lock()
	defer d.access.Unlock()
	if slices.Equal(d.hostAddresses, hostAddresses) {
		return nil
	}
	if err := d.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}
	d.hostAddresses = slices.Clone(hostAddresses)
	return nil
}

func (d *tcDataPlane) repairInfrastructure() (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return false, E.New("TC eBPF data plane is closed")
	}
	routingChanged, routingErr := d.routing.ensure()
	if d.delivery == nil {
		return routingChanged, routingErr
	}
	deliveryChanged, replaceDelivery, err := d.delivery.repair(d.backend, d.priority)
	if err != nil {
		return routingChanged || deliveryChanged, E.Errors(routingErr, err)
	}
	if !replaceDelivery {
		return routingChanged || deliveryChanged, routingErr
	}
	delivery, err := createTCDeliveryLink(d.backend, d.priority)
	if err != nil {
		return routingChanged || deliveryChanged, E.Errors(
			routingErr,
			E.Cause(err, "restore TC eBPF delivery link"),
		)
	}
	previousDelivery := d.delivery
	d.delivery = delivery
	if err = previousDelivery.Close(); err != nil {
		return true, E.Errors(routingErr, E.Cause(err, "remove stale TC eBPF delivery link"))
	}
	return true, routingErr
}

func (d *tcDeliveryLink) repair(backend *commonEBPF.TCBackend, priority uint16) (bool, bool, error) {
	if d == nil || d.redirect == nil || d.delivery == nil || d.filter == nil {
		return false, true, nil
	}
	redirect, err := netlink.LinkByName(d.redirectName)
	if err != nil && tcLinkNotFound(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	delivery, err := netlink.LinkByName(d.deliveryName)
	if err != nil && tcLinkNotFound(err) {
		return false, true, nil
	}
	if err != nil {
		return false, false, err
	}
	if redirect.Attrs().Index != d.redirect.Attrs().Index ||
		delivery.Attrs().Index != d.delivery.Attrs().Index {
		return false, true, nil
	}
	d.redirect = redirect
	d.delivery = delivery
	changed := false
	for _, link := range []netlink.Link{redirect, delivery} {
		if link.Attrs().Flags&net.FlagUp != 0 {
			continue
		}
		if err = netlink.LinkSetUp(link); err != nil {
			return changed, false, E.Cause(err, "restore TC eBPF delivery link ", link.Attrs().Name)
		}
		changed = true
	}
	filterAttached, err := tcFilterAttached(
		delivery,
		netlink.HANDLE_MIN_INGRESS,
		"sb_tc_deliver",
		tcDeliveryFilterHandle,
		priority,
	)
	if err != nil {
		return changed, false, err
	}
	if !filterAttached {
		if err = ensureTCClsact(delivery); err != nil {
			return changed, false, err
		}
		d.filter, err = attachTCFilter(
			delivery,
			netlink.HANDLE_MIN_INGRESS,
			backend.DeliveryIngressProgramFD(),
			"sb_tc_deliver",
			tcDeliveryFilterHandle,
			priority,
		)
		if err != nil {
			return changed, false, err
		}
		changed = true
	}
	for _, setting := range []struct {
		name  string
		value string
	}{
		{"rp_filter", "0"},
		{"accept_local", "1"},
	} {
		state, settingChanged, settingErr := setTCInterfaceSysctl(d.deliveryName, setting.name, setting.value)
		if errors.Is(settingErr, os.ErrNotExist) {
			return changed, true, nil
		}
		if settingErr != nil {
			return changed, false, settingErr
		}
		if settingChanged {
			d.sysctls = append(d.sysctls, state)
			changed = true
		}
	}
	return changed, false, nil
}

func (d *tcDataPlane) restoreState(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	closeErr := closeTCInterfaceAttachments(d.attachments)
	d.attachments = nil
	attachments, attachErr := attachTCInterfaces(
		d.backend,
		localInterface,
		sharedInterfaces,
		d.sharedSourceMACPolicy,
		d.priority,
	)
	d.attachments = attachments
	d.localInterface = localInterface
	d.sharedInterfaces = slices.Clone(sharedInterfaces)
	hostErr := d.backend.UpdateHostAddresses(hostAddresses)
	d.hostAddresses = slices.Clone(hostAddresses)
	restoreErr := E.Errors(closeErr, attachErr, hostErr)
	if restoreErr != nil {
		return E.Cause(restoreErr, "restore previous TC eBPF state")
	}
	restoreErr = d.backend.Enable()
	if restoreErr == nil {
		return nil
	}
	return E.Cause(restoreErr, "restore previous TC eBPF state")
}

func closeTCInterfaceAttachments(attachments []*tcInterfaceAttachment) error {
	var closeErr error
	for index := len(attachments) - 1; index >= 0; index-- {
		closeErr = E.Errors(closeErr, attachments[index].Close())
	}
	return closeErr
}

func (d *tcDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		roles := "local"
		if attachment.role.local && attachment.role.shared {
			roles = "local+shared"
		} else if attachment.role.shared {
			roles = "shared"
		}
		descriptions = append(
			descriptions,
			attachment.interfaceName+"("+roles+","+attachment.framing.String()+")",
		)
	}
	slices.Sort(descriptions)
	return descriptions
}

func (d *tcDataPlane) disable() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.backend == nil {
		return nil
	}
	return d.backend.Disable()
}

func attachTCInterface(
	link netlink.Link,
	backend *commonEBPF.TCBackend,
	role tcInterfaceRole,
	sharedSourceMACPolicy bool,
	priority uint16,
) (*tcInterfaceAttachment, error) {
	framing, err := tcLinkFraming(link)
	if err != nil {
		return nil, err
	}
	if role.shared && sharedSourceMACPolicy && framing != commonEBPF.TCLinkFramingEthernet {
		return nil, E.New("shared source MAC policy requires Ethernet framing on interface ", link.Attrs().Name)
	}
	interfaceLock, err := acquireTCInterfaceLock(link.Attrs().Name, link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	attachment := &tcInterfaceAttachment{
		interfaceName:  link.Attrs().Name,
		interfaceIndex: link.Attrs().Index,
		framing:        framing,
		role:           role,
		lock:           interfaceLock,
	}
	cleanup := func(startErr error) (*tcInterfaceAttachment, error) {
		return nil, E.Errors(startErr, attachment.Close())
	}
	if err = ensureTCClsact(link); err != nil {
		return cleanup(err)
	}
	if role.local {
		attachment.localFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_EGRESS,
			backend.LocalEgressProgramFD(framing),
			"sb_tc_local",
			tcLocalFilterHandle,
			priority,
		)
		if err != nil {
			return cleanup(err)
		}
	}
	if role.shared {
		attachment.sharedFilter, err = attachTCFilter(
			link,
			netlink.HANDLE_MIN_INGRESS,
			backend.SharedIngressProgramFD(framing),
			"sb_tc_shared",
			tcSharedFilterHandle,
			priority,
		)
		if err != nil {
			return cleanup(err)
		}
	}
	return attachment, nil
}

func (a *tcInterfaceAttachment) Close() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(
		detachTCFilter(a.sharedFilter),
		detachTCFilter(a.localFilter),
	)
	a.sharedFilter = nil
	a.localFilter = nil
	if a.lock != nil {
		closeErr = E.Errors(closeErr, a.lock.Close())
		a.lock = nil
	}
	return closeErr
}

func createTCDeliveryLink(backend *commonEBPF.TCBackend, priority uint16) (*tcDeliveryLink, error) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		return nil, err
	}
	attributes := netlink.NewLinkAttrs()
	attributes.Name = redirectName
	veth := &netlink.Veth{LinkAttrs: attributes, PeerName: deliveryName}
	if err = netlink.LinkAdd(veth); err != nil {
		return nil, E.Cause(err, "create TC eBPF delivery link")
	}
	delivery := &tcDeliveryLink{redirectName: redirectName, deliveryName: deliveryName}
	cleanup := func(startErr error) (*tcDeliveryLink, error) {
		return nil, E.Errors(startErr, delivery.Close())
	}
	delivery.redirect, err = netlink.LinkByName(redirectName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF redirect link"))
	}
	delivery.delivery, err = netlink.LinkByName(deliveryName)
	if err != nil {
		return cleanup(E.Cause(err, "find TC eBPF delivery peer"))
	}
	for _, link := range []netlink.Link{delivery.redirect, delivery.delivery} {
		if err = netlink.LinkSetUp(link); err != nil {
			return cleanup(E.Cause(err, "bring up TC eBPF delivery link ", link.Attrs().Name))
		}
	}
	for _, setting := range []struct {
		name  string
		value string
	}{
		{"rp_filter", "0"},
		{"accept_local", "1"},
	} {
		state, changed, settingErr := setTCInterfaceSysctl(deliveryName, setting.name, setting.value)
		if settingErr != nil {
			return cleanup(settingErr)
		}
		if changed {
			delivery.sysctls = append(delivery.sysctls, state)
		}
	}
	if err = ensureTCClsact(delivery.delivery); err != nil {
		return cleanup(err)
	}
	delivery.filter, err = attachTCFilter(
		delivery.delivery,
		netlink.HANDLE_MIN_INGRESS,
		backend.DeliveryIngressProgramFD(),
		"sb_tc_deliver",
		tcDeliveryFilterHandle,
		priority,
	)
	if err != nil {
		return cleanup(err)
	}
	deliveryHardwareAddress := delivery.delivery.Attrs().HardwareAddr
	if len(deliveryHardwareAddress) != len(commonEBPF.MACAddress{}) {
		return cleanup(E.New("TC eBPF delivery interface has invalid hardware address"))
	}
	var deliveryMAC commonEBPF.MACAddress
	copy(deliveryMAC[:], deliveryHardwareAddress)
	if err = backend.SetDeliveryInterface(uint32(delivery.redirect.Attrs().Index), deliveryMAC); err != nil {
		return cleanup(err)
	}
	return delivery, nil
}

func nextTCVethNames() (string, string, error) {
	for range 1024 {
		sequence := tcVethSequence.Add(1)
		suffix := fmt.Sprintf("%04x%04x", uint32(os.Getpid())&0xffff, sequence&0xffff)
		redirectName := "sbt" + suffix
		deliveryName := "sbd" + suffix
		if len(redirectName) > 15 || len(deliveryName) > 15 {
			return "", "", E.New("TC eBPF delivery link name exceeds Linux limit")
		}
		_, redirectErr := netlink.LinkByName(redirectName)
		_, deliveryErr := netlink.LinkByName(deliveryName)
		if tcLinkNotFound(redirectErr) && tcLinkNotFound(deliveryErr) {
			return redirectName, deliveryName, nil
		}
		if redirectErr != nil && !tcLinkNotFound(redirectErr) {
			return "", "", redirectErr
		}
		if deliveryErr != nil && !tcLinkNotFound(deliveryErr) {
			return "", "", deliveryErr
		}
	}
	return "", "", E.New("unable to allocate TC eBPF delivery link name")
}

func setTCInterfaceSysctl(interfaceName, setting, value string) (tcSysctlState, bool, error) {
	path := "/proc/sys/net/ipv4/conf/" + interfaceName + "/" + setting
	current, err := os.ReadFile(path)
	if err != nil {
		return tcSysctlState{}, false, E.Cause(err, "read ", setting, " for ", interfaceName)
	}
	original := strings.TrimSpace(string(current))
	if original == value {
		return tcSysctlState{}, false, nil
	}
	if err = os.WriteFile(path, []byte(value), 0o644); err != nil {
		return tcSysctlState{}, false, E.Cause(err, "set ", setting, " for ", interfaceName)
	}
	return tcSysctlState{path: path, original: original}, true, nil
}

func (d *tcDeliveryLink) Close() error {
	if d == nil {
		return nil
	}
	var closeErr error
	if d.filter != nil {
		closeErr = detachTCFilter(d.filter)
		d.filter = nil
	}
	for index := len(d.sysctls) - 1; index >= 0; index-- {
		state := d.sysctls[index]
		if err := os.WriteFile(state.path, []byte(state.original), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErr = E.Errors(closeErr, err)
		}
	}
	d.sysctls = nil
	if d.redirect != nil {
		if err := netlink.LinkDel(d.redirect); err != nil &&
			!errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			closeErr = E.Errors(closeErr, err)
		}
		d.redirect = nil
		d.delivery = nil
	} else if d.delivery != nil {
		if err := netlink.LinkDel(d.delivery); err != nil &&
			!errors.Is(err, unix.ENODEV) && !errors.Is(err, unix.ENOENT) {
			closeErr = E.Errors(closeErr, err)
		}
		d.delivery = nil
	}
	return closeErr
}

func (d *tcDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	var closeErr error
	if d.backend != nil {
		closeErr = d.backend.Disable()
	}
	for index := len(d.attachments) - 1; index >= 0; index-- {
		closeErr = E.Errors(closeErr, d.attachments[index].Close())
	}
	d.attachments = nil
	closeErr = E.Errors(closeErr, d.routing.Close())
	d.routing = nil
	closeErr = E.Errors(closeErr, d.delivery.Close())
	d.delivery = nil
	if d.backend != nil {
		closeErr = E.Errors(closeErr, d.backend.Close())
		d.backend = nil
	}
	return closeErr
}
