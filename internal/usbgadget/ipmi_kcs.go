package usbgadget

// ipmiKcsConfig defines the USB gadget function that carries IPMI to the host.
//
// Transport note: this is a *second* CDC-ACM (serial) function, not a literal
// KCS interface. Real IPMI KCS is a pair of LPC/ISA I/O ports the host reaches
// with inb/outb (see coreboot's drivers/ipmi/ipmi_kcs.c), and no USB function
// can appear in host I/O port space. What the host gets here is another
// /dev/ttyACM* node, over which we speak the IPMI serial transport (IPMI v2.0
// spec section 14 -- Basic Mode / Terminal Mode), which ipmitool reaches with:
//
//	ipmitool -I serial-basic -D /dev/ttyACM1:115200 chassis power status
//
// The name follows the device-type naming used in the UI/config; the wire
// protocol is IPMI-over-serial.
//
// Ordered after serialConsoleConfig (4000) so the console keeps acm.usb0 ->
// /dev/ttyGS0 and this function lands on acm.usb1 -> /dev/ttyGS1. Changing the
// relative order renumbers both ttyGS nodes and would silently swap the console
// and IPMI endpoints.
var ipmiKcsConfig = gadgetConfigItem{
	order:      4100,
	device:     "acm.usb1",
	path:       []string{"functions", "acm.usb1"},
	configPath: []string{"acm.usb1"},
}
