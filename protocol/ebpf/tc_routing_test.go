//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"

	"golang.org/x/sys/unix"
)

func TestTCPolicyRoutes(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		family   int
		prefixes []netip.Prefix
	}{
		{
			"IPv4",
			unix.AF_INET,
			[]netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
			},
		},
		{
			"IPv6",
			unix.AF_INET6,
			[]netip.Prefix{
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"),
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			routes := tcPolicyRoutes(7, testCase.family)
			if len(routes) != len(testCase.prefixes) {
				t.Fatalf("unexpected route count: %d", len(routes))
			}
			wantScope := uint8(unix.RT_SCOPE_HOST)
			if testCase.family == unix.AF_INET6 {
				wantScope = unix.RT_SCOPE_UNIVERSE
			}
			for index, route := range routes {
				if route.LinkIndex != 7 || route.Family != testCase.family ||
					route.Table != tcPolicyRoutingTable || route.Type != unix.RTN_LOCAL ||
					uint8(route.Scope) != wantScope || route.Protocol != unix.RTPROT_STATIC {
					t.Fatalf("unexpected route: %+v", route)
				}
				if destination := routeDestination(route.Dst); destination != testCase.prefixes[index] {
					t.Fatalf("unexpected destination: %s", destination)
				}
			}
		})
	}
}

func TestTCPolicyRule(t *testing.T) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := tcPolicyRule(family)
		if rule.Family != family || rule.Priority != tcPolicyRoutingPriority ||
			rule.Table != tcPolicyRoutingTable || rule.Mark != commonEBPF.TCRoutingMark ||
			!rule.MarkSet || rule.Mask != int(commonEBPF.TCRoutingMark) {
			t.Fatalf("unexpected policy rule: %+v", rule)
		}
		listed := *rule
		listed.MarkSet = false
		if !matchesTCPolicyRule(listed, *rule) {
			t.Fatal("listed policy rule did not match its expected rule")
		}
		listed.Table++
		if matchesTCPolicyRule(listed, *rule) {
			t.Fatal("conflicting policy rule matched")
		}
	}
}

func TestMatchesTCPolicyRoute(t *testing.T) {
	routes := tcPolicyRoutes(7, unix.AF_INET)
	if !matchesTCPolicyRoute(routes[0], routes) {
		t.Fatal("expected route did not match")
	}
	conflict := routes[0]
	conflict.LinkIndex++
	if matchesTCPolicyRoute(conflict, routes) {
		t.Fatal("route on another interface matched")
	}
	conflict = routes[0]
	conflict.Dst = tcPolicyRoutes(7, unix.AF_INET6)[0].Dst
	if matchesTCPolicyRoute(conflict, routes) {
		t.Fatal("route with another destination matched")
	}
}
