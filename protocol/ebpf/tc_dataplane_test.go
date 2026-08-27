//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestTCVethNamesFitLinuxLimit(t *testing.T) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(redirectName) > 15 || len(deliveryName) > 15 {
		t.Fatalf("delivery link names exceed Linux limit: %q %q", redirectName, deliveryName)
	}
	if redirectName == deliveryName {
		t.Fatal("delivery link names are identical")
	}
}
