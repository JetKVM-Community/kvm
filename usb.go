package kvm

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jetkvm/kvm/internal/usbgadget"
	"github.com/vishvananda/netlink"
)

var gadget *usbgadget.UsbGadget

// The CDC-ECM function (internal/usbgadget/ethernet.go) needs work here: the
// kernel creates a usb0 netdev on the gadget side, but leaves it down and
// unaddressed.

// USB CDC-ECM gadget interface. When the ethernet USB device is enabled the
// kernel exposes a usb0 netdev on the gadget side; bring it up with a link-local
// address so the attached host reaches the JetKVM over USB without any DHCP
// server (the host's CDC-ECM NIC auto-configures via APIPA in the same /16).
// This is done in the app (rather than a boot script) because usb0 only exists
// once the app configures the gadget, and it must be re-asserted after any USB
// re-enumeration/rebind.
const ethernetGadgetInterface = "usb0"
const ethernetGadgetAddress = "169.254.10.1/16"

// disableIPv6OnGadgetInterface turns IPv6 off on usb0. The RHI is a private,
// point-to-point IPv4 link (DSP0270 host interface): the UEFI payload is built
// with NETWORK_IP6_ENABLE=FALSE, so nothing on the host side can use IPv6, and
// the link-local address the kernel would otherwise autoconfigure only adds
// multicast/RA noise and a second address for Redfish clients to trip over.
//
// Writing disable_ipv6 also flushes any address the kernel already assigned, so
// this is safe to call after the interface is up and on every re-enumeration.
func disableIPv6OnGadgetInterface() {
	path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", ethernetGadgetInterface)
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		// A kernel built without IPv6 has no such knob, which is the desired
		// end state anyway -- log at debug and carry on.
		usbLogger.Debug().Err(err).Str("path", path).Msg("could not disable ipv6 on usb ethernet interface")
		return
	}
	usbLogger.Info().Str("iface", ethernetGadgetInterface).Msg("disabled ipv6 on usb ethernet interface")
}

// configureEthernetGadgetInterface brings the usb0 CDC-ECM interface up with a
// static address when the ethernet USB device is enabled. It is safe to call
// repeatedly: the address is applied with AddrReplace and a missing interface
// is retried briefly (the netdev appears shortly after the gadget is bound).
func configureEthernetGadgetInterface() {
	devices := effectiveUsbDevices()
	if devices == nil || !devices.Ethernet {
		return
	}

	var link netlink.Link
	var err error
	for i := 0; i < 20; i++ {
		if link, err = netlink.LinkByName(ethernetGadgetInterface); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		usbLogger.Warn().Err(err).Str("iface", ethernetGadgetInterface).Msg("usb ethernet interface not found; skipping IP config")
		return
	}

	if err := netlink.LinkSetUp(link); err != nil {
		usbLogger.Warn().Err(err).Str("iface", ethernetGadgetInterface).Msg("failed to bring up usb ethernet interface")
		return
	}

	disableIPv6OnGadgetInterface()

	addr, err := netlink.ParseAddr(ethernetGadgetAddress)
	if err != nil {
		usbLogger.Error().Err(err).Str("addr", ethernetGadgetAddress).Msg("invalid usb ethernet address")
		return
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		usbLogger.Warn().Err(err).Str("iface", ethernetGadgetInterface).Str("addr", ethernetGadgetAddress).Msg("failed to set usb ethernet address")
		return
	}

	usbLogger.Info().Str("iface", ethernetGadgetInterface).Str("addr", ethernetGadgetAddress).Msg("configured usb ethernet interface")
}

// hostLikelyPowered reports whether the managed host is drawing power, i.e.
// whether there is anything on the other end of the USB link to enumerate us.
//
// When a power-control extension is loaded this is authoritative. Without one
// the BMC genuinely cannot tell, and the answer is "assume powered" so behaviour
// is unchanged from before this distinction existed.
func hostLikelyPowered() bool {
	switch config.ActiveExtension {
	case "dc-power":
		return getDCState().IsOn
	case "atx-power":
		state, err := rpcGetATXState()
		if err != nil {
			return true
		}
		return state.Power
	default:
		return true
	}
}

// A host that was just powered on has not enumerated anything yet: it is still
// in early POST, and on this board USB initialisation is ~20 s in. "Not
// attached" is the expected state for that whole window, so recovery has to
// stay out of it -- a rebind landing mid-enumeration is precisely what breaks
// the host's view of the gadget. Observed on hardware 2026-07-30: without this,
// recovery fired 1 s after power-on and again 21 s later, straddling the window.
//
// The grace period is generous on purpose. Its only cost is delaying recovery
// from a genuine fault that happens to coincide with a power-on; its benefit is
// never corrupting the one enumeration pass that decides whether the host has a
// Redfish host interface for the rest of the boot.
const hostEnumerationGrace = 90 * time.Second

var (
	hostPowerOnAt   time.Time
	usbDetachedAt   time.Time
	hostPowerOnLock sync.Mutex
)

// noteHostPoweredOn records when the managed host last transitioned to powered.
func noteHostPoweredOn(at time.Time) {
	hostPowerOnLock.Lock()
	defer hostPowerOnLock.Unlock()
	hostPowerOnAt = at
}

// noteUsbDetached records when the gadget stopped being attached, and clears
// that once it is attached again.
//
// This is what makes the grace cover a *warm reboot*, not just a power-on. A
// rebooting host drops off the bus and re-enumerates without any power
// transition, so keying the grace on power-on alone left the reboot case
// unprotected: the gadget detached, nothing looked recent, and recovery rebound
// within ~5 s -- in the middle of the host's re-enumeration. That is the same
// destructive rebind the power-on grace exists to prevent, and it is what left
// the host sitting at its boot splash after `systemctl reboot` while the BMC
// logged repeated rebind cycles.
func noteUsbDetached(detached bool, at time.Time) {
	hostPowerOnLock.Lock()
	defer hostPowerOnLock.Unlock()

	if !detached {
		usbDetachedAt = time.Time{}
		return
	}
	if usbDetachedAt.IsZero() {
		usbDetachedAt = at
	}
}

// withinHostEnumerationGrace reports whether the host is still inside a window
// where it is expected not to have enumerated us yet -- either because it was
// just powered on, or because it just dropped off the bus and is presumably
// coming back (reset, reboot, firmware re-enumeration).
func withinHostEnumerationGrace(now time.Time) bool {
	hostPowerOnLock.Lock()
	defer hostPowerOnLock.Unlock()

	if !hostPowerOnAt.IsZero() && now.Sub(hostPowerOnAt) < hostEnumerationGrace {
		return true
	}
	if !usbDetachedAt.IsZero() && now.Sub(usbDetachedAt) < hostEnumerationGrace {
		return true
	}
	return false
}

// ensureHostInterfaceReady makes the USB gadget presentable to a host that is
// about to enumerate it, and is the reason the RHI works at all on a cold boot.
//
// The managed host enumerates USB exactly once, early in firmware, and takes
// what it finds: the UEFI payload binds a CDC-ECM NIC there or it has no Redfish
// host interface for the rest of the boot. If the gadget is mid-rebind at that
// moment the host sees a device disappear underneath it -- observed on hardware
// 2026-07-30 as a NUC that sat at the boot splash indefinitely while the BMC
// logged repeated "rebinding USB gadget" / "full gadget reconfigure" cycles.
//
// So on the power-on transition: bind the UDC if it is not bound, then re-assert
// usb0's address. Deliberately no rebind of an already-bound gadget -- that is
// the very disruption this exists to avoid.
func ensureHostInterfaceReady(reason string) {
	if gadget == nil {
		return
	}

	devices := effectiveUsbDevices()
	if devices == nil || !devices.Ethernet {
		usbLogger.Debug().Str("reason", reason).Msg("usb ethernet disabled; not preparing host interface")
		return
	}

	state := gadget.GetUsbState()
	if state == usbgadget.USBStateNotAttached || state == usbgadget.USBStateUnknown {
		// This is the one rebind that is safe and necessary: the host has just
		// been powered and cannot have enumerated anything yet, so there is no
		// in-flight enumeration to disturb.
		if err := gadget.RebindUsb(true); err != nil {
			usbLogger.Warn().Err(err).Str("reason", reason).Msg("failed to bind USB gadget for host interface")
		} else {
			usbLogger.Info().Str("reason", reason).Msg("bound USB gadget ahead of host enumeration")
		}
	}

	configureEthernetGadgetInterface()

	usbLogger.Info().
		Str("reason", reason).
		Str("usb_state", gadget.GetUsbState()).
		Msg("USB host interface ready for host enumeration")
}

func effectiveUsbDevices() *usbgadget.Devices {
	if config == nil || config.UsbDevices == nil {
		return nil
	}

	devices := *config.UsbDevices
	return &devices
}

func effectiveAudioEnabled() bool {
	return config != nil &&
		config.UsbDevices != nil &&
		config.AudioEnabled &&
		config.UsbDevices.Audio
}

// initUsbGadget initializes the USB gadget.
// call it only after the config is loaded.
func initUsbGadget() {
	// Pin the CDC-ECM MACs to this unit before the gadget is built, so usb0's
	// address survives reboots (see internal/usbgadget/ethernet.go).
	usbgadget.SetEthernetMACSeed(GetDeviceID())

	usbConfig := config.UsbConfig
	if usbConfig != nil && usbConfig.SerialNumber == "" {
		// Give the gadget a USB serial number.
		//
		// Without one the host has no stable way to name this device. udev
		// builds /dev/serial/by-id/ out of the manufacturer, product and serial
		// strings, so an empty serial leaves every JetKVM sharing one path --
		// and the raw /dev/ttyACM<N> is worse, since N is assigned in
		// enumeration order and moves when any other CDC-ACM device is present.
		//
		// The device ID is the right value: it is already what the CDC-ECM MACs
		// and the IPMI GUID are derived from, so the serial console, the Redfish
		// host interface and the BMC's own identity all trace to the same unit.
		usbConfig.SerialNumber = GetDeviceID()
	}

	gadget = usbgadget.NewUsbGadget(
		"jetkvm",
		effectiveUsbDevices(),
		usbConfig,
		usbLogger,
	)

	setUSBRecoveryTimer(time.Now())

	go func() {
		for {
			checkUSBState()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	gadget.SetOnKeyboardStateChange(func(state usbgadget.KeyboardState) {
		if currentSession != nil {
			currentSession.reportHidRPCKeyboardLedState(state)
		}
	})

	gadget.SetOnKeysDownChange(func(state usbgadget.KeysDownState) {
		if currentSession != nil {
			currentSession.enqueueKeysDownState(state)
			currentSession.resetKeepAliveTime()
		}
	})

	// open the keyboard hid file to listen for keyboard events
	if err := gadget.OpenKeyboardHidFile(); err != nil {
		usbLogger.Error().Err(err).Msg("failed to open keyboard hid file")
	}

	// bring up the usb0 CDC-ECM interface (retries until the netdev appears)
	go configureEthernetGadgetInterface()
}

// rpcHidReport wraps a HID gadget call with the common guard (skip if USB not
// ready) and error suppression (swallow transient HID errors during rebind).
func rpcHidReport(fn func() error) error {
	if !usbReadyForHidReports() {
		return nil
	}
	if err := fn(); err != nil && !usbgadget.IsHIDTemporarilyUnavailableError(err) {
		return err
	}
	return nil
}

func rpcKeyboardReport(modifier byte, keys []byte) error {
	return rpcHidReport(func() error { return gadget.KeyboardReport(modifier, keys) })
}

func rpcKeypressReport(key byte, press bool) error {
	return rpcHidReport(func() error { return gadget.KeypressReport(key, press) })
}

func rpcAbsMouseReport(x int, y int, buttons uint8) error {
	return rpcHidReport(func() error { return gadget.AbsMouseReport(x, y, buttons) })
}

func rpcRelMouseReport(dx int8, dy int8, buttons uint8) error {
	return rpcHidReport(func() error { return gadget.RelMouseReport(dx, dy, buttons) })
}

func rpcWheelReport(wheelY int8, wheelX int8) error {
	return rpcHidReport(func() error {
		if gadget.HasAbsoluteMouse() {
			return gadget.AbsMouseWheelReport(wheelY, wheelX)
		}
		return gadget.RelMouseWheelReport(wheelY, wheelX)
	})
}

func rpcWakeHost() error {
	if gadget == nil {
		return fmt.Errorf("USB gadget is not initialized")
	}

	state := gadget.GetUsbState()
	if state == usbgadget.USBStateNotAttached || state == usbgadget.USBStateUnknown {
		return nil
	}

	for i := 0; i < 3; i++ {
		if err := gadget.WakeReport(true); err != nil && !usbgadget.IsHIDTemporarilyUnavailableError(err) {
			return err
		}

		time.Sleep(50 * time.Millisecond)

		if err := gadget.WakeReport(false); err != nil && !usbgadget.IsHIDTemporarilyUnavailableError(err) {
			return err
		}

		time.Sleep(150 * time.Millisecond)
	}

	return nil
}

func rpcGetKeyboardLedState() (state usbgadget.KeyboardState) {
	return gadget.GetKeyboardState()
}

func rpcGetKeysDownState() (state usbgadget.KeysDownState) {
	return gadget.GetKeysDownState()
}

var (
	usbState     = usbgadget.USBStateUnknown
	usbStateLock sync.Mutex

	usbEmulationDesired = true
	lastUSBRecoveryTry  time.Time
)

func usbReadyForHidReports() bool {
	usbStateLock.Lock()
	state := usbState
	usbStateLock.Unlock()
	return state != usbgadget.USBStateNotAttached && state != usbgadget.USBStateUnknown
}

func rpcGetUSBState() (state string) {
	return gadget.GetUsbState()
}

func setUSBEmulationDesired(enabled bool) {
	usbStateLock.Lock()
	defer usbStateLock.Unlock()

	usbEmulationDesired = enabled
}

func setUSBRecoveryTimer(lastAttempt time.Time) {
	usbStateLock.Lock()
	defer usbStateLock.Unlock()

	lastUSBRecoveryTry = lastAttempt
}

func attemptUSBRecovery(state string) string {
	now := time.Now()

	// "not attached" is the correct, healthy state when the managed host is
	// powered off -- there is no host to attach to. Rebinding on a 5-second loop
	// in that situation fixes nothing and is actively harmful: each rebind tears
	// down and recreates every function, including the CDC-ECM interface the
	// Redfish host interface depends on, so a rebind landing in the host's
	// power-on enumeration window costs it the RHI NIC (or hangs its USB
	// enumeration outright). Wait for the host to come back instead; the
	// power-on transition calls ensureHostInterfaceReady().
	if !hostLikelyPowered() {
		usbLogger.Debug().Str("state", state).Msg("host is powered off; not rebinding USB gadget")
		return state
	}

	// Powered, but either just powered on or freshly off the bus -- in both
	// cases it is expected not to have enumerated us yet, and a rebind now is
	// the thing most likely to break its one enumeration pass.
	if withinHostEnumerationGrace(now) {
		usbLogger.Debug().
			Str("state", state).
			Msg("host is inside its enumeration window (power-on or reset); not rebinding USB gadget")
		return state
	}

	usbStateLock.Lock()
	desired := usbEmulationDesired
	lastAttempt := lastUSBRecoveryTry
	shouldRecover := usbgadget.ShouldAttemptUSBRecovery(state, desired, lastAttempt, now)
	if shouldRecover {
		lastUSBRecoveryTry = now
	}
	usbStateLock.Unlock()

	if !shouldRecover {
		return state
	}

	usbLogger.Warn().Msg("USB gadget is detached while USB emulation should be enabled; rebinding USB gadget")

	if err := gadget.RebindUsb(true); err != nil {
		usbLogger.Warn().Err(err).Msg("failed to recover USB gadget by rebinding USB device controller")
		return state
	}

	// Clear stale /dev/hidg* handles from the pre-rebind gadget instance.
	// The next write/open must use the newly recreated device nodes.
	gadget.ResetHIDFiles()

	// A rebind can recreate the usb0 netdev; re-assert its address.
	go configureEthernetGadgetInterface()

	// After rebind, the kernel recreates /dev/hidg* but the character
	// devices take several seconds to become usable (ENXIO until the
	// function driver attaches). Retry the keyboard HID file open with
	// increasing delays up to ~20 seconds total.
	delays := []time.Duration{
		1 * time.Second,
		1 * time.Second,
		2 * time.Second,
		2 * time.Second,
		3 * time.Second,
		3 * time.Second,
		4 * time.Second,
		4 * time.Second,
	}
	tryReopenKeyboard := func(openDelays []time.Duration, reason string) bool {
		for _, delay := range openDelays {
			time.Sleep(delay)
			if err := gadget.ReopenKeyboardHidFile(); err == nil {
				usbLogger.Info().Str("reason", reason).Msg("keyboard HID file reopened successfully after USB recovery")
				return true
			}
		}
		return false
	}

	if tryReopenKeyboard(delays, "udc_rebind") {
		return gadget.GetUsbState()
	}

	usbLogger.Warn().Msg("keyboard HID file not ready after UDC rebind; attempting full USB gadget reconfigure")

	if err := gadget.UpdateGadgetConfig(); err != nil {
		usbLogger.Warn().Err(err).Msg("failed to recover USB gadget with full gadget reconfigure")
		return gadget.GetUsbState()
	}
	gadget.ResetHIDFiles()

	if !tryReopenKeyboard(delays, "gadget_reconfigure") {
		usbLogger.Warn().Msg("keyboard HID file not ready after full USB recovery retry window")
	}

	return gadget.GetUsbState()
}

func triggerUSBStateUpdate() {
	go func() {
		if currentSession == nil {
			usbLogger.Info().Msg("No active RPC session, skipping USB state update")
			return
		}
		writeJSONRPCEvent("usbState", usbState, currentSession)
	}()
}

func checkUSBState() {
	newState := gadget.GetUsbState()

	// Record the detach *before* considering recovery: a host that is rebooting
	// looks exactly like this, and the grace window is measured from here.
	noteUsbDetached(newState == usbgadget.USBStateNotAttached, time.Now())

	if newState == usbgadget.USBStateNotAttached {
		newState = attemptUSBRecovery(newState)
	}

	usbStateLock.Lock()
	defer usbStateLock.Unlock()

	if newState != usbgadget.USBStateNotAttached {
		// Once USB is attached again, clear recovery rate limiting so any future
		// detach can be recovered immediately.
		lastUSBRecoveryTry = time.Time{}
	}

	if newState == usbState {
		return
	}

	oldState := usbState
	usbState = newState
	usbLogger.Info().Str("from", oldState).Str("to", newState).Msg("USB state changed")

	if newState != usbgadget.USBStateNotAttached {
		openErr := gadget.OpenKeyboardHidFile()
		if openErr != nil {
			usbLogger.Warn().Err(openErr).Str("state", newState).Msg("HID chardev broken after state change, attempting corrective rebind")

			lastUSBRecoveryTry = time.Now()
			usbStateLock.Unlock()

			gadget.ResetHIDFiles()
			if rebindErr := gadget.RebindUsb(true); rebindErr == nil {
				time.Sleep(1 * time.Second)
				_ = gadget.OpenKeyboardHidFile()
			}

			usbStateLock.Lock()
			usbState = gadget.GetUsbState()
			lastUSBRecoveryTry = time.Now()
		}
	}

	requestDisplayUpdate(false, "usb_state_changed")
	triggerUSBStateUpdate()
}
