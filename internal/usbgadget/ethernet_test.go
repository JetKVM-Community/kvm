package usbgadget

import (
	"net"
	"testing"
)

func TestDeriveGadgetMAC(t *testing.T) {
	const seed = "31a9d7bc56e8b54d"

	dev := deriveGadgetMAC(seed, "dev")
	host := deriveGadgetMAC(seed, "host")

	for name, s := range map[string]string{"dev": dev, "host": host} {
		hw, err := net.ParseMAC(s)
		if err != nil {
			t.Fatalf("%s addr %q is not a valid MAC: %v", name, s, err)
		}
		// Must be unicast: the kernel rejects a multicast dev_addr/host_addr.
		if hw[0]&0x01 != 0 {
			t.Errorf("%s addr %q is multicast", name, s)
		}
		// Must be locally administered so it cannot collide with a real OUI.
		if hw[0]&0x02 == 0 {
			t.Errorf("%s addr %q is not locally administered", name, s)
		}
	}

	// The two ends of the link must not share an address.
	if dev == host {
		t.Errorf("dev and host addresses are identical: %q", dev)
	}

	// Stable across calls, or the interface name churns on every boot.
	if again := deriveGadgetMAC(seed, "dev"); again != dev {
		t.Errorf("not deterministic: %q then %q", dev, again)
	}

	// Distinct per device.
	if other := deriveGadgetMAC("0000000000000000", "dev"); other == dev {
		t.Errorf("different seeds produced the same address: %q", dev)
	}
}

func TestSetEthernetMACSeedEmptyIsNoop(t *testing.T) {
	t.Cleanup(func() {
		delete(ethernetConfig.attrs, "dev_addr")
		delete(ethernetConfig.attrs, "host_addr")
	})

	delete(ethernetConfig.attrs, "dev_addr")
	delete(ethernetConfig.attrs, "host_addr")

	// An empty seed must leave the attributes absent, so configfs is never
	// handed an empty string and the kernel keeps its random addresses.
	SetEthernetMACSeed("")
	if _, ok := ethernetConfig.attrs["dev_addr"]; ok {
		t.Error("empty seed set dev_addr")
	}

	SetEthernetMACSeed("31a9d7bc56e8b54d")
	if ethernetConfig.attrs["dev_addr"] == "" {
		t.Error("non-empty seed did not set dev_addr")
	}
	if ethernetConfig.attrs["dev_addr"] == ethernetConfig.attrs["host_addr"] {
		t.Error("dev_addr and host_addr must differ")
	}
}
