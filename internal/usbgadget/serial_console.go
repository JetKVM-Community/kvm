package usbgadget

var serialConsoleConfig = gadgetConfigItem{
	order:      4000,
	device:     "acm.usb0",
	path:       []string{"functions", "acm.usb0"},
	configPath: []string{"acm.usb0"},
	attrs: gadgetAttributes{
		// f_acm can run its port in one of two modes, and the difference is
		// invisible until you try to type at it.
		//
		// With console=1 the function is registered through
		// gserial_console_setup() as a *kernel console* -- a printk sink. The
		// gadget transmits, the host receives, and that is the whole of it:
		// nothing wires the OUT endpoint back to /dev/ttyGS0, so everything the
		// host writes is dropped without an error anywhere. Measured on this
		// board: BMC -> host delivered fine while 0 of 30 host -> BMC writes
		// arrived, with an open, DTR-asserted, raw-mode fd at both ends.
		//
		// This kernel defaults the attribute to 1, so leaving it unset gets the
		// console behaviour by accident. A BMC serial console has to be
		// bidirectional -- an operator on "ipmitool sol activate" needs to
		// answer a boot prompt, not just watch one -- so pin it to 0.
		"console": "0",
	},
}
