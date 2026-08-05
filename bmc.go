package kvm

import (
	"fmt"

	"github.com/jetkvm/kvm/internal/usbgadget"
)

// Board Management Controller mode.
//
// Redfish (redfish.go) and IPMI (ipmi.go) are two views of one thing: this
// device acting as a BMC for the host plugged into its USB port. Both are gated
// on Config.BmcEnabled rather than each carrying its own on/off, because they
// share a precondition neither can check for itself -- the USB gadget has to be
// presenting the functions the management paths run over.
//
// That coupling is why enabling BMC mode pins the USB class selection. The
// alternative is an operator unticking "USB Ethernet" in an unrelated settings
// panel and discovering, at the next boot of the managed host, that Redfish
// stopped working -- with nothing connecting cause to effect.

// bmcUsbDevices is the USB function set BMC mode requires.
//
// Each entry is load-bearing rather than a default worth keeping:
//
//   - Keyboard and both mice: the operator still needs to drive firmware setup
//     screens, which is the case where no in-band path exists at all.
//   - MassStorage: virtual media. Redfish exposes it and it is how an OS gets
//     installed on a machine with no OS.
//   - SerialConsole (CDC-ACM): a serial console to the host, independent of
//     video. This is also the only path over which IPMI SOL could ever work --
//     the device's own UART is claimed by the ATX/DC power extension.
//   - Ethernet (CDC-ECM): the 169.254.10.0/24 link the host's firmware speaks
//     Redfish over. Without it there is no host interface and no inventory.
//
// Audio is excluded deliberately. It is a convenience for interactive use, not
// a management path, and it costs USB endpoints on a controller where they are
// finite.
var bmcUsbDevices = usbgadget.Devices{
	Keyboard:      true,
	AbsoluteMouse: true,
	RelativeMouse: true,
	MassStorage:   true,
	SerialConsole: true,
	Ethernet:      true,
	Audio:         false,
}

// bmcModeEnabled reports whether this device is acting as a BMC.
func bmcModeEnabled() bool {
	return config != nil && config.BmcEnabled
}

// usbDevicesLocked reports whether the USB class selection may be changed.
// Callers should surface this to the operator rather than silently ignoring a
// write, so the UI can explain *why* the control is disabled.
func usbDevicesLocked() bool {
	return bmcModeEnabled()
}

// applyBmcUsbDevices pins the USB gadget to the BMC function set. Called when
// BMC mode is switched on and at startup, so a config edited by hand cannot
// leave the device claiming to be a BMC while missing the link it manages over.
func applyBmcUsbDevices() error {
	if !bmcModeEnabled() {
		return nil
	}

	wanted := bmcUsbDevices
	if config.UsbDevices != nil && *config.UsbDevices == wanted {
		return nil
	}

	config.UsbDevices = &wanted
	if err := SaveConfig(); err != nil {
		return fmt.Errorf("persist BMC USB devices: %w", err)
	}

	logger.Info().Msg("USB gadget pinned to the Board Management Controller function set")
	return nil
}

// setBmcEnabled turns BMC mode on or off, applying everything that hangs off it.
//
// Turning it off deliberately leaves the USB function set alone. The operator
// asked to stop managing the host, not to yank a virtual disk or a serial
// console out from under whatever is using it right now; the controls simply
// become editable again.
func setBmcEnabled(enabled bool) error {
	if config.BmcEnabled == enabled {
		return nil
	}

	config.BmcEnabled = enabled

	if enabled {
		if err := applyBmcUsbDevices(); err != nil {
			return err
		}
	} else {
		// IPMI is meaningless without BMC mode, and leaving a listener up after
		// management was turned off would be the surprising reading of "off".
		config.IPMIEnabled = false
	}

	if err := SaveConfig(); err != nil {
		return fmt.Errorf("persist BMC mode: %w", err)
	}

	// Reconcile the IPMI listener with the new state. A failure here is logged
	// rather than returned: BMC mode itself has already changed and is saved.
	if err := ipmiRestart(); err != nil {
		ipmiLogger.Error().Err(err).Msg("failed to restart IPMI after a BMC mode change")
	}

	logger.Info().Bool("enabled", enabled).Msg("Board Management Controller mode changed")
	return nil
}

// validateBmcConfig rejects a configuration that claims capabilities it cannot
// deliver, at the point of change rather than at the next boot.
func validateBmcConfig(c *Config) error {
	if !c.BmcEnabled {
		// IPMI without BMC mode has no USB link to manage over.
		if c.IPMIEnabled {
			return fmt.Errorf("IPMI requires Board Management Controller mode to be enabled")
		}
		return nil
	}

	if c.UsbDevices != nil {
		if !c.UsbDevices.Ethernet {
			return fmt.Errorf("Board Management Controller mode requires USB Ethernet: " +
				"the host's firmware speaks Redfish over it")
		}
		if !c.UsbDevices.MassStorage {
			return fmt.Errorf("Board Management Controller mode requires USB Mass Storage for virtual media")
		}
	}

	return validateIPMIConfig(c)
}
