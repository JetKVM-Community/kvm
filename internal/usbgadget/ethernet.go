package usbgadget

import (
	"crypto/sha256"
	"fmt"
)

// ethernetConfig defines the USB CDC-ECM (Ethernet Control Model) gadget
// function. It exposes a virtual Ethernet interface to the USB host, following
// the same configfs pattern as the CDC-ACM serial console function: the kernel
// creates the function directory, and the transaction layer symlinks it into
// the active configuration.
//
// dev_addr/host_addr are filled in by SetEthernetMACSeed. Left unset, the
// kernel invents random addresses on every boot, which is fine for a link-local
// ping but breaks two things that matter here: the attached host names the
// interface after the MAC it sees (enx<mac>), and DMTF DSP0270 Redfish
// host-interface discovery locates the BMC's NIC *by* MAC address.
var ethernetConfig = gadgetConfigItem{
	order:      3500,
	device:     "ecm.usb0",
	path:       []string{"functions", "ecm.usb0"},
	configPath: []string{"ecm.usb0"},
	attrs:      gadgetAttributes{},
}

// SetEthernetMACSeed pins the CDC-ECM MAC addresses to values derived from
// seed, making them stable across reboots and unique per device. Call it before
// NewUsbGadget; an empty seed leaves the addresses unset so the kernel keeps
// its random-per-boot behaviour.
//
// The seed is supplied by the caller rather than read here so this package does
// not have to know how the device identifies itself.
func SetEthernetMACSeed(seed string) {
	if seed == "" {
		return
	}
	ethernetConfig.attrs["dev_addr"] = deriveGadgetMAC(seed, "dev")
	ethernetConfig.attrs["host_addr"] = deriveGadgetMAC(seed, "host")
}

// deriveGadgetMAC builds a stable MAC address from a seed and a role tag. The
// two roles must differ: dev_addr is the JetKVM's own usb0, host_addr is what
// the attached host's NIC gets, and the kernel rejects the pair if they match.
func deriveGadgetMAC(seed, role string) string {
	sum := sha256.Sum256([]byte("jetkvm/ecm/" + role + "/" + seed))
	b := sum[:6]

	// Locally administered and unicast (IEEE 802-2014, 8.2): set bit 1 of the
	// first octet so the address cannot collide with a real assigned OUI, and
	// clear bit 0 so it is not read as a multicast address -- which the kernel
	// would reject outright.
	b[0] = (b[0] | 0x02) &^ 0x01

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
