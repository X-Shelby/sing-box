//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

type objectMapLayout struct {
	keySize   uint32
	valueSize uint32
}

func TestEmbeddedTCObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadTC, map[string]objectMapLayout{
		"tc_control":             {4, 72},
		"tc_listener_sockets":    {4, 4},
		"tc_assignment":          {40, 12},
		"tc_socket_bypass":       {8, 1},
		"tc_uid_policy":          {8, 1},
		"tc_bypass_ipv4":         {8, 1},
		"tc_bypass_ipv6":         {20, 1},
		"tc_include_source_ipv4": {8, 1},
		"tc_include_source_ipv6": {20, 1},
		"tc_exclude_source_ipv4": {8, 1},
		"tc_exclude_source_ipv6": {20, 1},
		"tc_include_source_mac":  {8, 1},
		"tc_exclude_source_mac":  {8, 1},
		"tc_host_ipv4":           {4, 1},
		"tc_host_ipv6":           {16, 1},
	}, []string{
		"classifier/local_egress_ethernet",
		"classifier/local_egress_raw_ip",
		"classifier/shared_ingress_ethernet",
		"classifier/shared_ingress_raw_ip",
		"classifier/delivery_ingress",
	})
}

func testEmbeddedObjectLayout(
	t *testing.T,
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]objectMapLayout,
	sections []string,
) {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range maps {
		actual := spec.Maps[name]
		if actual == nil {
			t.Errorf("missing map %q", name)
			continue
		}
		if actual.KeySize != expected.keySize || actual.ValueSize != expected.valueSize {
			t.Errorf(
				"map %q has key/value size %d/%d, want %d/%d",
				name,
				actual.KeySize,
				actual.ValueSize,
				expected.keySize,
				expected.valueSize,
			)
		}
	}
	availableSections := make(map[string]bool, len(spec.Programs))
	for _, program := range spec.Programs {
		availableSections[program.SectionName] = true
	}
	for _, section := range sections {
		if !availableSections[section] {
			t.Errorf("missing program section %q", section)
		}
	}
}
