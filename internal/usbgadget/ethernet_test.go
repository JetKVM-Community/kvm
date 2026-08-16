package usbgadget

import (
	"net"
	"testing"
)

// assertUsableGadgetMAC checks the two properties configfs will reject on.
func assertUsableGadgetMAC(t *testing.T, name, s string) {
	t.Helper()

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

func TestDeriveGadgetMAC(t *testing.T) {
	const seed = "31a9d7bc56e8b54d"

	dev := deriveGadgetMAC(seed, "dev")
	alt := deriveGadgetMAC(seed, "dev-alt")

	assertUsableGadgetMAC(t, "dev", dev)
	assertUsableGadgetMAC(t, "dev-alt", alt)

	// The collision fallback in SetEthernetMACSeed is only useful if a
	// different role tag actually yields a different address.
	if dev == alt {
		t.Errorf("dev and dev-alt derived the same address: %q", dev)
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

func TestRedfishHostInterfaceMACIsFixedAndUsable(t *testing.T) {
	assertUsableGadgetMAC(t, "host", RedfishHostInterfaceMAC)

	// The constant is not arbitrary: it is the address the original
	// per-device derivation produced for the reference unit, and therefore
	// the one already compiled into deployed host firmware. Changing it
	// silently breaks DSP0270 discovery on every host built against it --
	// the link comes up and no traffic ever flows. If this assertion is in
	// your way, the firmware constant has to change in lockstep.
	if want := deriveGadgetMAC("31a9d7bc56e8b54d", "host"); RedfishHostInterfaceMAC != want {
		t.Errorf("host MAC %q no longer matches deployed firmware, which expects %q",
			RedfishHostInterfaceMAC, want)
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
	// host_addr is the fixed contract value, not derived from the seed: the
	// host firmware matches on it and cannot know this device's ID.
	if got := ethernetConfig.attrs["host_addr"]; got != RedfishHostInterfaceMAC {
		t.Errorf("host_addr = %q, want the fixed %q", got, RedfishHostInterfaceMAC)
	}
	if ethernetConfig.attrs["dev_addr"] == ethernetConfig.attrs["host_addr"] {
		t.Error("dev_addr and host_addr must differ")
	}

	// A second device must still get its own dev_addr while presenting the
	// same host_addr -- that is the whole point of the change.
	SetEthernetMACSeed("9b179f6a9ab585e9")
	if ethernetConfig.attrs["dev_addr"] == deriveGadgetMAC("31a9d7bc56e8b54d", "dev") {
		t.Error("dev_addr did not change with the seed")
	}
	if got := ethernetConfig.attrs["host_addr"]; got != RedfishHostInterfaceMAC {
		t.Errorf("host_addr varied by device: %q", got)
	}
}
