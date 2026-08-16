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

// RedfishHostInterfaceMAC is the MAC the attached host's NIC gets, and it is a
// fixed constant rather than a per-device value.
//
// It is a contract with the host firmware. DSP0270 discovery rejects the
// interface unless the SMBIOS type 42 MAC byte-matches the host NIC's actual
// MAC (RedfishDiscoverDxe compares the two with CompareMem and gives up on
// mismatch), and the firmware carries its copy as a compile-time constant. When
// this was derived per device, moving a host between JetKVMs silently broke the
// host interface: USB still enumerated and the link came up, but discovery
// discarded the NIC, so the firmware never configured an address and never sent
// a byte. Nothing logged a cause on either side. The alternative to a constant
// is a firmware build per BMC.
//
// Sharing one address across devices is safe here because the CDC-ECM link is
// point-to-point and unrouted -- configureEthernetGadgetInterface gives it a
// link-local address and no gateway -- so no two of these are ever on the same
// segment. The addressing already assumes one BMC per host in any case: both
// ends are fixed at 169.254.10.1/.2, so a host with two of these would collide
// on IP whatever the MAC said.
//
// Do not bridge usb0 onto a real segment without revisiting this.
//
// The value is already locally administered and unicast (0xda: bit 1 set, bit 0
// clear), the same invariant deriveGadgetMAC enforces, and it is the value
// existing firmware images are built against -- so adopting it needs no
// firmware change and no reflash.
const RedfishHostInterfaceMAC = "da:a7:62:23:3e:f5"

// SetEthernetMACSeed pins the CDC-ECM MAC addresses. dev_addr -- the JetKVM's
// own usb0 -- is derived from seed, so it stays stable across reboots and
// unique per device. host_addr is the fixed RedfishHostInterfaceMAC. Call it
// before NewUsbGadget; an empty seed leaves both unset so the kernel keeps its
// random-per-boot behaviour.
//
// The seed is supplied by the caller rather than read here so this package does
// not have to know how the device identifies itself.
func SetEthernetMACSeed(seed string) {
	if seed == "" {
		return
	}

	// The kernel rejects the function if the two addresses match. A derived
	// dev_addr colliding with the fixed host_addr is a ~2^-46 event, but it
	// would present as an unexplained gadget failure on one device in the
	// fleet and nowhere else, so re-derive with a distinct role instead.
	dev := deriveGadgetMAC(seed, "dev")
	if dev == RedfishHostInterfaceMAC {
		dev = deriveGadgetMAC(seed, "dev-alt")
	}

	ethernetConfig.attrs["dev_addr"] = dev
	ethernetConfig.attrs["host_addr"] = RedfishHostInterfaceMAC
}

// deriveGadgetMAC builds a stable MAC address from a seed and a role tag.
//
// Only dev_addr -- the JetKVM's own usb0 -- is derived. host_addr is the fixed
// RedfishHostInterfaceMAC; see the note there for why it cannot vary per
// device. The role tag remains part of the hash input so the "dev-alt" fallback
// yields a different address.
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
