package kvm

import (
	"context"
	"errors"
	"testing"

	"github.com/bougou/go-ipmi/pkg/hal"
	"github.com/bougou/go-ipmi/pkg/types"

	"github.com/jetkvm/kvm/internal/usbgadget"
)

// restoreRedfishHost snapshots the shared host state so a test that stages a
// boot override does not leak it into the next one.
func restoreRedfishHost(t *testing.T) {
	t.Helper()
	// Staging an override writes through to the config (and thence to disk), so
	// a test that touches host state needs a redirected config too -- otherwise
	// it dereferences a nil *Config, or worse, saves over the real one.
	withTestConfig(t)
	redfishHostMu.RLock()
	saved := redfishHost
	redfishHostMu.RUnlock()
	t.Cleanup(func() {
		redfishHostMu.Lock()
		redfishHost = saved
		redfishHostMu.Unlock()
	})
}

// The whole point of the IPMI boot path is that it writes the state the host's
// firmware already reads. If these two ever diverge, "ipmitool chassis bootdev"
// silently stops reaching the host.
func TestIPMIBootFlagsWriteTheRedfishOverride(t *testing.T) {
	restoreRedfishHost(t)
	chassis := &jetkvmChassis{}

	tests := []struct {
		name        string
		selector    types.BootDeviceSelector
		persist     bool
		wantTarget  string
		wantEnabled string
	}{
		{"pxe once", types.BootDeviceSelectorForcePXE, false, "Pxe", "Once"},
		{"pxe persistent", types.BootDeviceSelectorForcePXE, true, "Pxe", "Continuous"},
		{"disk once", types.BootDeviceSelectorForceHardDrive, false, "Hdd", "Once"},
		{"firmware setup", types.BootDeviceSelectorForceBIOSSetup, false, "BiosSetup", "Once"},
		{"no override clears", types.BootDeviceSelectorNoOverride, false, "None", "Disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := chassis.SetBootFlags(context.Background(), &types.BootOptionParam_BootFlags{
				BootFlagsValid:     true,
				Persist:            tt.persist,
				BootDeviceSelector: tt.selector,
			})
			if err != nil {
				t.Fatalf("SetBootFlags: %v", err)
			}

			redfishHostMu.RLock()
			gotTarget := redfishHost.BootOverrideTarget
			gotEnabled := redfishHost.BootOverrideEnabled
			redfishHostMu.RUnlock()

			if gotTarget != tt.wantTarget || gotEnabled != tt.wantEnabled {
				t.Errorf("staged %s/%s, want %s/%s",
					gotTarget, gotEnabled, tt.wantTarget, tt.wantEnabled)
			}

			// Whatever was staged must be a target the host firmware accepts,
			// or it will be dropped at the next boot with no diagnostic.
			if !redfishValidBootTarget(gotTarget) {
				t.Errorf("staged %q, which redfishValidBootTarget rejects", gotTarget)
			}
		})
	}
}

// Clearing the valid bit means "forget the override", regardless of what the
// selector field happens to hold.
func TestIPMIBootFlagsInvalidBitClearsOverride(t *testing.T) {
	restoreRedfishHost(t)
	chassis := &jetkvmChassis{}

	if err := chassis.SetBootFlags(context.Background(), &types.BootOptionParam_BootFlags{
		BootFlagsValid:     true,
		BootDeviceSelector: types.BootDeviceSelectorForcePXE,
	}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	if err := chassis.SetBootFlags(context.Background(), &types.BootOptionParam_BootFlags{
		BootFlagsValid:     false,
		BootDeviceSelector: types.BootDeviceSelectorForcePXE,
	}); err != nil {
		t.Fatalf("clear: %v", err)
	}

	redfishHostMu.RLock()
	defer redfishHostMu.RUnlock()
	if redfishHost.BootOverrideTarget != "None" || redfishHost.BootOverrideEnabled != "Disabled" {
		t.Errorf("after clearing: %s/%s, want None/Disabled",
			redfishHost.BootOverrideTarget, redfishHost.BootOverrideEnabled)
	}
}

// A selector this host cannot honour must fail at the command rather than be
// accepted and dropped -- the failure would otherwise surface a boot later.
func TestIPMIUnsupportedBootSelectorIsRefused(t *testing.T) {
	restoreRedfishHost(t)
	chassis := &jetkvmChassis{}

	unsupported := []types.BootDeviceSelector{
		types.BootDeviceSelectorForceCDROM,
		types.BootDeviceSelectorForceDiagnosticPartition,
		types.BootDeviceSelectorForceRemoteMedia,
		types.BootDeviceSelectorForceFloppy,
	}

	for _, sel := range unsupported {
		err := chassis.SetBootFlags(context.Background(), &types.BootOptionParam_BootFlags{
			BootFlagsValid:     true,
			BootDeviceSelector: sel,
		})
		if !errors.Is(err, hal.ErrNotSupported) {
			t.Errorf("selector %s returned %v, want ErrNotSupported", sel, err)
		}
	}
}

// GetBootFlags is what an operator reads back to confirm a staged override, so
// it has to reproduce what was set -- including via the Redfish path.
func TestIPMIBootFlagsRoundTrip(t *testing.T) {
	restoreRedfishHost(t)
	chassis := &jetkvmChassis{}

	// Stage the way a Redfish PATCH does, then read back over IPMI.
	redfishHostMu.Lock()
	redfishHost.BootOverrideTarget = "Pxe"
	redfishHost.BootOverrideEnabled = "Continuous"
	redfishHostMu.Unlock()

	flags, err := chassis.GetBootFlags(context.Background())
	if err != nil {
		t.Fatalf("GetBootFlags: %v", err)
	}
	if !flags.BootFlagsValid {
		t.Error("BootFlagsValid is false; an override is staged")
	}
	if !flags.Persist {
		t.Error("Persist is false, but the override is Continuous")
	}
	if flags.BootDeviceSelector != types.BootDeviceSelectorForcePXE {
		t.Errorf("selector = %s, want ForcePXE", flags.BootDeviceSelector)
	}
	// The managed host boots UEFI; reporting "PC compatible" would misdescribe
	// how the firmware acts on the selector.
	if flags.BIOSBootType != types.BIOSBootTypeEFI {
		t.Errorf("BIOSBootType = %v, want EFI", flags.BIOSBootType)
	}
}

func TestIPMIBootSelectorMappingIsSymmetric(t *testing.T) {
	for _, target := range redfishBootOverrideTargets {
		sel := ipmiBootSelector(target)
		back, ok := ipmiBootTarget(sel)
		if !ok {
			t.Errorf("%q maps to selector %s, which maps back to nothing", target, sel)
			continue
		}
		if back != target {
			t.Errorf("%q round-tripped to %q", target, back)
		}
	}
}

// "No power extension loaded" is a third state that IPMI cannot express, and
// reporting it as "off" would be a guess dressed as a measurement.
func TestIPMIPowerStateErrorsWithoutAnExtension(t *testing.T) {
	withTestConfig(t).ActiveExtension = ""

	if _, err := (&jetkvmChassis{}).PowerState(context.Background()); err == nil {
		t.Error("PowerState returned no error with no power extension active")
	}
}

// Warm reset means "ask the OS to reboot". The DC extension can only cut the
// rail, and a cold cycle presented as a warm reset is how a clean shutdown
// turns into a dirty one.
func TestIPMIWarmResetUnsupportedOnDCPower(t *testing.T) {
	withTestConfig(t).ActiveExtension = "dc-power"

	if err := (&jetkvmChassis{}).WarmReset(context.Background()); !errors.Is(err, hal.ErrNotSupported) {
		t.Errorf("WarmReset on dc-power = %v, want ErrNotSupported", err)
	}
}

// The host's identity comes from its own SMBIOS, reported over the Redfish host
// interface. FRU must hand back those values rather than invent any.
func TestIPMIFRUReportsTheHostIdentity(t *testing.T) {
	restoreRedfishHost(t)

	redfishHostMu.Lock()
	redfishHost.Manufacturer = "Intel"
	redfishHost.Model = "NUC5i7RYB"
	redfishHost.SerialNumber = "G6RY62000ABC"
	redfishHostMu.Unlock()

	data, err := (&jetkvmFRUStore{}).Read(context.Background(), ipmiFRUDeviceID)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("FRU is empty")
	}
	for _, want := range []string{"Intel", "NUC5i7RYB", "G6RY62000ABC"} {
		if !containsASCII(data, want) {
			t.Errorf("FRU does not carry %q", want)
		}
	}
}

// A FRU write would either be discarded at the next boot or would overwrite a
// measurement with an assertion.
func TestIPMIFRUIsReadOnly(t *testing.T) {
	store := &jetkvmFRUStore{}
	if err := store.Write(context.Background(), ipmiFRUDeviceID, []byte{0}); !errors.Is(err, hal.ErrNotSupported) {
		t.Errorf("Write = %v, want ErrNotSupported", err)
	}
	if _, err := store.Read(context.Background(), 7); !errors.Is(err, hal.ErrNotFound) {
		t.Errorf("Read of an unknown device = %v, want ErrNotFound", err)
	}
}

// Cipher suite 0 negotiates no authentication and no encryption. Offering it
// would make every other control here decorative.
func TestIPMICipherSuiteZeroIsNotOffered(t *testing.T) {
	for _, id := range ipmiCipherSuites {
		if id == types.CipherSuiteID0 {
			t.Fatal("cipher suite 0 is offered; it authenticates nothing")
		}
	}
	if len(ipmiCipherSuites) == 0 {
		t.Fatal("no cipher suites offered; no session could be established")
	}
}

// Absent subsystems must be nil rather than stubs that answer, so the handlers
// return a real completion code instead of fabricated data.
func TestIPMIHALReportsAbsentSubsystemsAsNil(t *testing.T) {
	h := newJetKVMHAL()
	if h.Chassis() == nil {
		t.Error("Chassis is nil; power and boot control would be unavailable")
	}
	if h.Storage() == nil {
		t.Error("Storage is nil; FRU would be unavailable")
	}
	if h.Sensors() != nil {
		t.Error("Sensors is non-nil, but this BMC reads no host sensors")
	}
	if h.GPIO() != nil || h.I2C() != nil || h.Network() != nil {
		t.Error("a subsystem this device cannot serve is non-nil")
	}
	// No sensors means no sensor data records to describe them.
	if h.Storage().SDR() != nil {
		t.Error("SDR is non-nil, but there are no sensors")
	}
}

func TestValidateIPMIConfig(t *testing.T) {
	base := func() *Config {
		return &Config{
			IPMIEnabled:       true,
			EncryptedPassword: "sealed",
		}
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"disabled skips validation", func(c *Config) { c.IPMIEnabled = false; c.EncryptedPassword = "" }, false},
		{"no stored credential", func(c *Config) { c.EncryptedPassword = "" }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			err := validateIPMIConfig(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIPMIConfig = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// IPMI must not be reachable with the web UI's credential, and must not be on
// unless someone turned it on.
func TestIPMIIsDisabledByDefault(t *testing.T) {
	c := getDefaultConfig()
	if c.IPMIEnabled {
		t.Error("IPMI is enabled by default")
	}
	if c.EncryptedPassword != "" {
		t.Error("a reversible credential exists by default")
	}
}

func containsASCII(haystack []byte, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == needle {
			return true
		}
	}
	return false
}

// A staged override is an instruction the host has not read yet, so it has to
// survive a BMC restart. Losing it is silent: the operator staged a target and
// then watches the wrong thing boot.
func TestBootOverrideIsPersistedAndRestored(t *testing.T) {
	restoreRedfishHost(t)
	cfg := config

	redfishSetBootOverride("Pxe", "Once")

	if cfg.HostBootOverrideTarget != "Pxe" || cfg.HostBootOverrideEnabled != "Once" {
		t.Fatalf("config holds %s/%s, want Pxe/Once -- the override would not survive a restart",
			cfg.HostBootOverrideTarget, cfg.HostBootOverrideEnabled)
	}

	// Simulate the restart: memory is empty, config is not.
	redfishHostMu.Lock()
	redfishHost.BootOverrideTarget = "None"
	redfishHost.BootOverrideEnabled = "Disabled"
	redfishHostMu.Unlock()

	redfishRestoreBootOverride()

	redfishHostMu.RLock()
	defer redfishHostMu.RUnlock()
	if redfishHost.BootOverrideTarget != "Pxe" || redfishHost.BootOverrideEnabled != "Once" {
		t.Errorf("after restart: %s/%s, want Pxe/Once",
			redfishHost.BootOverrideTarget, redfishHost.BootOverrideEnabled)
	}
}

// A persisted target the firmware cannot apply must not be restored: it would
// sit there looking staged and do nothing at the next boot.
func TestRestoreRejectsAnUnsupportedPersistedTarget(t *testing.T) {
	restoreRedfishHost(t)
	cfg := config
	cfg.HostBootOverrideTarget = "Floppy"
	cfg.HostBootOverrideEnabled = "Once"

	redfishHostMu.Lock()
	redfishHost.BootOverrideTarget = "None"
	redfishHost.BootOverrideEnabled = "Disabled"
	redfishHostMu.Unlock()

	redfishRestoreBootOverride()

	redfishHostMu.RLock()
	defer redfishHostMu.RUnlock()
	if redfishHost.BootOverrideTarget != "None" {
		t.Errorf("restored unsupported target %q", redfishHost.BootOverrideTarget)
	}
}

// An IPMI-staged override must persist too -- ipmitool users expect boot flags
// to survive a BMC reset.
func TestIPMIBootFlagsArePersisted(t *testing.T) {
	restoreRedfishHost(t)
	cfg := config

	err := (&jetkvmChassis{}).SetBootFlags(context.Background(), &types.BootOptionParam_BootFlags{
		BootFlagsValid:     true,
		Persist:            true,
		BootDeviceSelector: types.BootDeviceSelectorForceHardDrive,
	})
	if err != nil {
		t.Fatalf("SetBootFlags: %v", err)
	}
	if cfg.HostBootOverrideTarget != "Hdd" || cfg.HostBootOverrideEnabled != "Continuous" {
		t.Errorf("config holds %s/%s, want Hdd/Continuous",
			cfg.HostBootOverrideTarget, cfg.HostBootOverrideEnabled)
	}
}

// BMC mode is the precondition both management protocols share: without the
// USB functions they run over, neither has a path to the host.
func TestBmcModePinsTheUsbFunctionSet(t *testing.T) {
	cfg := withTestConfig(t)
	cfg.BmcEnabled = true
	cfg.UsbDevices = &usbgadget.Devices{Keyboard: true} // everything else off

	if err := applyBmcUsbDevices(); err != nil {
		// SaveConfig writes to a path that does not exist off-device; the
		// pinning itself is what matters here.
		t.Logf("applyBmcUsbDevices reported %v (save is expected to fail off-device)", err)
	}

	got := *cfg.UsbDevices
	for name, enabled := range map[string]bool{
		"Ethernet":      got.Ethernet,
		"MassStorage":   got.MassStorage,
		"SerialConsole": got.SerialConsole,
		"Keyboard":      got.Keyboard,
		"AbsoluteMouse": got.AbsoluteMouse,
	} {
		if !enabled {
			t.Errorf("%s is off, but BMC mode depends on it", name)
		}
	}
	// Audio is a convenience, not a management path, and costs USB endpoints.
	if got.Audio {
		t.Error("Audio is on; the BMC set excludes it deliberately")
	}
}

// The lock has to be real at the RPC layer, not just greyed out in the UI.
func TestUsbClassesLockedOnlyInBmcMode(t *testing.T) {
	cfg := withTestConfig(t)

	cfg.BmcEnabled = false
	if usbDevicesLocked() {
		t.Error("USB classes are locked with BMC mode off")
	}

	cfg.BmcEnabled = true
	if !usbDevicesLocked() {
		t.Error("USB classes are editable with BMC mode on")
	}
}

// A configuration that claims management capability it cannot deliver should be
// refused where it is set, not discovered at the next boot.
func TestValidateBmcConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"off is fine", Config{}, false},
		{"IPMI without BMC mode", Config{IPMIEnabled: true}, true},
		{
			"BMC mode without ethernet",
			Config{BmcEnabled: true, UsbDevices: &usbgadget.Devices{MassStorage: true}},
			true,
		},
		{
			"BMC mode without mass storage",
			Config{BmcEnabled: true, UsbDevices: &usbgadget.Devices{Ethernet: true}},
			true,
		},
		{
			"BMC mode with the required functions",
			Config{BmcEnabled: true, UsbDevices: &bmcUsbDevices},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateBmcConfig(&tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("validateBmcConfig = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
