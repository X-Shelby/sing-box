//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sagernet/netlink"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

type KernelProbeMode string

const (
	KernelProbeModeAll    KernelProbeMode = "all"
	KernelProbeModeLocal  KernelProbeMode = "local"
	KernelProbeModeShared KernelProbeMode = "shared"
)

type KernelProbeStatus string

const (
	KernelProbePass    KernelProbeStatus = "PASS"
	KernelProbeWarn    KernelProbeStatus = "WARN"
	KernelProbeFail    KernelProbeStatus = "FAIL"
	KernelProbeUnknown KernelProbeStatus = "UNKNOWN"
)

type KernelProbeImportance string

const (
	KernelProbeRequired    KernelProbeImportance = "required"
	KernelProbePerformance KernelProbeImportance = "performance"
)

type KernelProbeOptions struct {
	Mode          KernelProbeMode
	Network       []string
	InterfaceName string
}

type KernelProbeFinding struct {
	Status     KernelProbeStatus     `json:"status"`
	Scope      string                `json:"scope"`
	Importance KernelProbeImportance `json:"importance"`
	Feature    string                `json:"feature"`
	Detail     string                `json:"detail"`
}

type KernelProbeProgram struct {
	ID       CiliumEBPF.ProgramID
	Name     string
	Type     CiliumEBPF.ProgramType
	MapCount int
}

type KernelProbeReport struct {
	Platform       string
	KernelRelease  string
	Architecture   string
	Mode           KernelProbeMode
	Network        []string
	Findings       []KernelProbeFinding
	ActivePrograms []KernelProbeProgram
	ActiveStateErr error
}

func (r *KernelProbeReport) Add(
	status KernelProbeStatus,
	scope string,
	importance KernelProbeImportance,
	feature string,
	detail string,
) {
	r.Findings = append(r.Findings, KernelProbeFinding{
		Status:     status,
		Scope:      scope,
		Importance: importance,
		Feature:    feature,
		Detail:     detail,
	})
}

func (r *KernelProbeReport) RequiredFailures() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Status == KernelProbeFail && finding.Importance == KernelProbeRequired {
			count++
		}
	}
	return count
}

func (r *KernelProbeReport) Counts() map[KernelProbeStatus]int {
	counts := make(map[KernelProbeStatus]int, 4)
	for _, finding := range r.Findings {
		counts[finding.Status]++
	}
	return counts
}

func ProbeKernel(options KernelProbeOptions) (*KernelProbeReport, error) {
	if options.Mode == "" {
		options.Mode = KernelProbeModeAll
	}
	switch options.Mode {
	case KernelProbeModeAll, KernelProbeModeLocal, KernelProbeModeShared:
	default:
		return nil, fmt.Errorf("invalid eBPF probe mode: %s", options.Mode)
	}
	enableTCP, enableUDP, network, err := parseKernelProbeNetwork(options.Network)
	if err != nil {
		return nil, err
	}
	memlockErr := raiseMemlockLimit()

	report := &KernelProbeReport{
		Platform:      kernelProbePlatform(),
		KernelRelease: kernelProbeRelease(),
		Architecture:  runtime.GOARCH,
		Mode:          options.Mode,
		Network:       network,
	}
	probeCommonCapabilities(report, memlockErr)
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeLocal {
		probeLocalCapabilities(report, enableTCP, enableUDP)
	}
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeShared {
		probeSharedCapabilities(report, options.InterfaceName)
	}
	report.ActivePrograms, report.ActiveStateErr = probeActivePrograms()
	return report, nil
}

func probeCommonCapabilities(report *KernelProbeReport, memlockErr error) {
	if os.Geteuid() == 0 {
		report.Add(KernelProbePass, "common", KernelProbeRequired, "privileged process",
			"The process has UID 0. Direct probes below still detect capability, LSM, or seccomp restrictions.")
	} else {
		report.Add(KernelProbeUnknown, "common", KernelProbeRequired, "BPF and network administration privileges",
			"Run as root or grant the BPF, system-administration, and network-administration capabilities required by the selected data path.")
	}

	version, versionErr := features.LinuxVersionCode()
	if versionErr != nil {
		report.Add(KernelProbeUnknown, "common", KernelProbeRequired, "Linux 5.7 compatibility baseline",
			"The running kernel version could not be read: "+shortProbeError(versionErr))
	} else if version < kernelVersionCode(5, 7, 0) {
		report.Add(KernelProbeFail, "common", KernelProbeRequired, "Linux 5.7 compatibility baseline",
			fmt.Sprintf("The running kernel reports %s; this implementation targets Linux 5.7 or newer.", formatKernelVersionCode(version)))
	} else {
		report.Add(KernelProbePass, "common", KernelProbeRequired, "Linux 5.7 compatibility baseline",
			fmt.Sprintf("The running kernel reports %s. Individual feature probes remain authoritative for vendor kernels.", formatKernelVersionCode(version)))
	}
	probeLPMTrieUpdateSafety(report)

	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Hash,
		"Stores source MAC and exact host-address policy.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Array,
		"Stores runtime controls.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LRUHash,
		"Stores bounded original-flow assignment metadata.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LPMTrie,
		"Stores UID, source CIDR, and destination bypass policies.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.SockMap,
		"Stores transparent TCP listener sockets for assignment.")
	probeProgramType(report, "common", KernelProbeRequired, CiliumEBPF.SchedCLS,
		"Runs the unified local-egress, shared-ingress, and delivery-ingress TC classifiers.")
	for _, helper := range []struct {
		fn     asm.BuiltinFunc
		name   string
		detail string
	}{
		{asm.FnMapLookupElem, "bpf_map_lookup_elem", "Reads controls, policy, listeners, and assignment state."},
		{asm.FnMapUpdateElem, "bpf_map_update_elem", "Publishes original-flow assignment metadata."},
		{asm.FnMapDeleteElem, "bpf_map_delete_elem", "Removes failed assignments."},
		{asm.FnGetSocketCookie, "bpf_get_socket_cookie", "Identifies sing-box sockets registered for local interception bypass."},
		{asm.FnGetSocketUid, "bpf_get_socket_uid", "Applies configured local UID or Android package policy."},
		{asm.FnRedirect, "bpf_redirect", "Redirects selected local packets into the internal delivery veth."},
		{asm.FnSkbStoreBytes, "bpf_skb_store_bytes", "Addresses selected local packets to the internal delivery peer."},
		{asm.FnSkbChangeHead, "bpf_skb_change_head", "Adds Ethernet framing when the local interface carries raw IP."},
		{asm.FnSkcLookupTcp, "bpf_skc_lookup_tcp", "Finds transparent TCP listeners and established sockets."},
		{asm.FnSkLookupUdp, "bpf_sk_lookup_udp", "Finds the transparent UDP listener."},
		{asm.FnSkAssign, "bpf_sk_assign", "Assigns packets to transparent TCP and UDP sockets without rewriting tuples."},
		{asm.FnSkRelease, "bpf_sk_release", "Releases socket references returned by lookup helpers."},
	} {
		probeProgramHelper(report, "common", KernelProbeRequired, CiliumEBPF.SchedCLS, helper.fn, helper.name, helper.detail)
	}

	probeMemlockLimit(report, memlockErr)
	probeBPFJIT(report)
}

func probeLPMTrieUpdateSafety(report *KernelProbeReport) {
	safety := currentLPMTrieKernelSafety()
	switch {
	case !safety.detected:
		report.Add(KernelProbeUnknown, "common", KernelProbeRequired, "LPM trie policy update safety",
			"The running kernel release could not be checked for the Linux 6.6 LPM trie update defect.")
	case safety.unsafe:
		report.Add(KernelProbeWarn, "common", KernelProbeRequired, "LPM trie policy update safety",
			"Linux 6.6.0-6.6.46 can panic under UBSAN when LPM trie policies are updated. Default exact-host policy is safe, but UID, source CIDR, and bypass CIDR policies require 6.6.47 or fix "+lpmTrieFlexibleKeyFix+".")
	default:
		report.Add(KernelProbePass, "common", KernelProbeRequired, "LPM trie policy update safety",
			"The running kernel is not in the known unsafe Linux 6.6.0-6.6.46 range, or exposes the fixed flexible-key layout.")
	}
}

func probeMemlockLimit(report *KernelProbeReport, raiseErr error) {
	var limit unix.Rlimit
	readErr := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit)
	status, detail := memlockProbeResult(limit, readErr, raiseErr)
	report.Add(status, "common", KernelProbeRequired, "locked-memory limit", detail)
}

func memlockProbeResult(limit unix.Rlimit, readErr error, raiseErr error) (KernelProbeStatus, string) {
	if readErr != nil {
		detail := "The process limit could not be read: " + shortProbeError(readErr)
		if raiseErr != nil {
			detail += "; automatic adjustment also failed: " + shortProbeError(raiseErr)
		}
		return KernelProbeUnknown, detail
	}
	if limit.Cur == unix.RLIM_INFINITY {
		return KernelProbePass, "RLIMIT_MEMLOCK is unlimited after automatic adjustment."
	}
	detail := fmt.Sprintf(
		"Automatic adjustment left RLIMIT_MEMLOCK at soft=%d, hard=%d bytes.",
		limit.Cur,
		limit.Max,
	)
	if raiseErr != nil {
		detail += " Adjustment failed: " + shortProbeError(raiseErr) + "."
	}
	detail += " EPERM from subsequent BPF probes may be inconclusive on kernels that charge BPF objects against this limit."
	return KernelProbeWarn, detail
}

func probeLocalCapabilities(report *KernelProbeReport, enableTCP bool, enableUDP bool) {
	const scope = "local"
	protocols := selectedProtocolDetail(enableTCP, enableUDP)
	report.Add(KernelProbePass, scope, KernelProbeRequired, "unified TC local interception", protocols+" use the default-interface egress classifier and internal delivery veth.")
}

func probeSharedCapabilities(report *KernelProbeReport, interfaceName string) {
	const scope = "shared"
	report.Add(KernelProbePass, scope, KernelProbeRequired, "unified TC shared interception",
		"Configured downstream interfaces use the ingress classifier and transparent socket assignment.")
	probeSharedInterface(report, interfaceName)
}

func selectedProtocolDetail(enableTCP, enableUDP bool) string {
	switch {
	case enableTCP && enableUDP:
		return "TCP and UDP"
	case enableTCP:
		return "TCP"
	default:
		return "UDP"
	}
}

func probeMapType(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	mapType CiliumEBPF.MapType,
	detail string,
) {
	reportFeatureResult(report, scope, importance, "BPF map type "+mapType.String(), detail, features.HaveMapType(mapType))
}

func probeProgramType(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	programType CiliumEBPF.ProgramType,
	detail string,
) {
	reportFeatureResult(report, scope, importance, "BPF program type "+programType.String(), detail, features.HaveProgramType(programType))
}

func probeProgramHelper(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	programType CiliumEBPF.ProgramType,
	helper asm.BuiltinFunc,
	name string,
	detail string,
) {
	reportFeatureResult(report, scope, importance, name+" for "+programType.String(), detail,
		features.HaveProgramHelper(programType, helper))
}

func reportFeatureResult(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	feature string,
	detail string,
	err error,
) {
	status := classifyKernelProbeError(err)
	if err != nil && status == KernelProbeUnknown {
		detail += " Probe was inconclusive: " + shortProbeError(err)
	}
	report.Add(status, scope, importance, feature, detail)
}

func classifyKernelProbeError(err error) KernelProbeStatus {
	switch {
	case err == nil:
		return KernelProbePass
	case errors.Is(err, CiliumEBPF.ErrNotSupported):
		return KernelProbeFail
	default:
		return KernelProbeUnknown
	}
}

func probeSharedInterface(report *KernelProbeReport, interfaceName string) {
	const scope = "shared"
	if interfaceName == "" {
		report.Add(KernelProbeUnknown, scope, KernelProbeRequired, "downstream interface",
			"Pass --interface with one configured shared.interface value to validate its TC framing.")
		return
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "interface "+interfaceName,
			"The interface is absent. Android hotspot interfaces may exist only while tethering is enabled: "+shortProbeError(err))
		return
	}
	attributes := link.Attrs()
	framing := ClassifyTCLinkFraming(attributes.EncapType, len(attributes.HardwareAddr))
	if framing == TCLinkFramingUnsupported {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "TC interface framing "+interfaceName,
			"The interface uses unsupported link encapsulation "+attributes.EncapType+".")
		return
	}
	report.Add(KernelProbePass, scope, KernelProbeRequired, "TC interface framing "+interfaceName,
		"The interface uses supported "+framing.String()+" framing ("+attributes.EncapType+").")
}

func probeBPFJIT(report *KernelProbeReport) {
	data, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	if err != nil {
		report.Add(KernelProbeUnknown, "common", KernelProbePerformance, "BPF JIT",
			"The JIT control is not readable; some kernels enable the JIT without exposing this sysctl.")
		return
	}
	value := strings.TrimSpace(string(data))
	if value == "0" {
		report.Add(KernelProbeWarn, "common", KernelProbePerformance, "BPF JIT",
			"The JIT is disabled; interpreting packet-path programs can substantially reduce throughput.")
		return
	}
	report.Add(KernelProbePass, "common", KernelProbePerformance, "BPF JIT",
		"The kernel reports bpf_jit_enable="+value+".")
}

func probeActivePrograms() ([]KernelProbeProgram, error) {
	var programs []KernelProbeProgram
	var current CiliumEBPF.ProgramID
	for {
		next, err := CiliumEBPF.ProgramGetNextID(current)
		if errors.Is(err, os.ErrNotExist) {
			return programs, nil
		}
		if err != nil {
			return programs, err
		}
		current = next
		program, err := CiliumEBPF.NewProgramFromID(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return programs, err
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			return programs, infoErr
		}
		if !strings.HasPrefix(info.Name, "sb_tc_") {
			continue
		}
		mapIDs, _ := info.MapIDs()
		programs = append(programs, KernelProbeProgram{
			ID:       next,
			Name:     info.Name,
			Type:     info.Type,
			MapCount: len(mapIDs),
		})
	}
}

func parseKernelProbeNetwork(configured []string) (bool, bool, []string, error) {
	if len(configured) == 0 {
		configured = []string{"tcp", "udp"}
	}
	var enableTCP, enableUDP bool
	for _, protocol := range configured {
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "tcp":
			enableTCP = true
		case "udp":
			enableUDP = true
		default:
			return false, false, nil, fmt.Errorf("invalid eBPF probe network: %s", protocol)
		}
	}
	network := make([]string, 0, 2)
	if enableTCP {
		network = append(network, "tcp")
	}
	if enableUDP {
		network = append(network, "udp")
	}
	return enableTCP, enableUDP, network, nil
}

func kernelProbePlatform() string {
	if runtime.GOOS == "android" {
		return "Android"
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "OpenWrt"
	}
	return "Linux"
}

func kernelProbeRelease() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "unknown"
	}
	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

func kernelVersionCode(major uint32, minor uint32, patch uint32) uint32 {
	if patch > 255 {
		patch = 255
	}
	return major<<16 | minor<<8 | patch
}

func formatKernelVersionCode(version uint32) string {
	return fmt.Sprintf("%d.%d.%d", version>>16, version>>8&0xff, version&0xff)
}

func shortProbeError(err error) string {
	message := strings.ReplaceAll(err.Error(), "\n", " ")
	const limit = 240
	if len(message) > limit {
		return message[:limit] + "..."
	}
	return message
}
