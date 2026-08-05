package kvm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bougou/go-ipmi/pkg/bmc"
	"github.com/bougou/go-ipmi/pkg/hal"
	"github.com/bougou/go-ipmi/pkg/handlers"
	"github.com/bougou/go-ipmi/pkg/server"
	"github.com/bougou/go-ipmi/pkg/transport/udp"
	"github.com/bougou/go-ipmi/pkg/types"
)

// An IPMI 2.0 BMC over RMCP+, serving the same managed host as redfish.go.
//
// This is a second protocol over one set of primitives, not a second
// implementation. Every operation lands on the same functions the Redfish
// handlers call -- redfishPowerState, performRedfishReset, and the
// redfishHost boot-override fields -- so the two views cannot disagree about
// the host, and neither becomes the "real" one.
//
// The boot override is the reason this is worth having rather than merely
// possible. IPMI's boot device selector (v2.0 Table 28-6) and Redfish's
// BootSourceOverrideTarget encode the same choice -- network, disk, firmware
// setup -- and the host's firmware already reads that choice from this BMC over
// the Redfish host interface on every boot. Pointing SetBootFlags at the same
// state means "ipmitool chassis bootdev pxe" reaches the host through machinery
// that already exists and is known to work, with no firmware change at all.
//
// What is deliberately absent:
//
//   - SOL, for now. Not for want of a serial port: BMC mode always presents a
//     CDC-ACM console to the host (see bmc.go), which is exactly what SOL needs.
//     The device's own UART is unavailable -- config.ActiveExtension gives that
//     single port to the ATX/DC power extension -- but the USB one is free.
//     What is missing is in go-ipmi: its server dispatches only the session-setup
//     and IPMI payload types, so PayloadTypeSOL (0x01) is dropped before any
//     handler sees it, and there are no Activate/Deactivate Payload commands.
//     Adding it means wrapping transport.PacketConn to intercept SOL payloads
//     before they reach that switch; everything needed is exported.
//   - Sensors. This BMC has no in-band view of the host: over the USB link it
//     sees a NIC and nothing else. There are no host temperatures, voltages or
//     fan speeds to report, so SensorHAL is nil and "ipmitool sensor" is empty.
//     The Redfish side has the same gap for the same reason.
//   - SEL. Nothing here generates events, so an always-empty log would be a
//     claim rather than data.
//
// hal.HAL permits nil for absent subsystems, and the handlers turn that into
// the proper completion code, so each of those degrades into an honest "not
// supported" rather than a fabricated answer.

// None of these are configurable, deliberately. This device has exactly one
// account -- the device password shared with the web UI and Redfish -- and
// IPMI is a third view of it, not a separate service to administer. A
// configurable port or username would be a second identity to keep in sync,
// and the standard values are what every IPMI client assumes anyway.
const (
	// ipmiPort is the RMCP port assigned by IANA, where every client looks.
	ipmiPort = 623

	// ipmiUserSlot is the IPMI user slot the account occupies. Slot 1 is
	// reserved for the anonymous/null user, so the first usable slot is 2.
	ipmiUserSlot = 2

	// ipmiChannel is the LAN channel number this BMC serves. Channel 1 is the
	// conventional first LAN channel and what ipmitool assumes by default.
	ipmiChannel = 1

	// ipmiUsername is the account name RAKP matches on. Web and Redfish accept
	// any name and check only the device password; IPMI cannot -- RAKP keys on
	// the name -- so the one shared account needs a fixed one here.
	ipmiUsername = "admin"
)

// ipmiCipherSuites are the RMCP+ cipher suites this BMC will negotiate:
// 3 (HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128) and 17 (HMAC-SHA256 /
// HMAC-SHA256-128 / AES-CBC-128).
//
// Suite 0 is excluded on purpose and must stay excluded. It negotiates no
// authentication and no encryption at all -- a session established under it is
// unauthenticated, which historically turned "the BMC is reachable" into "the
// BMC is owned". It is not offered here and cannot be selected.
var ipmiCipherSuites = []types.CipherSuiteID{
	types.CipherSuiteID3,
	types.CipherSuiteID17,
}

var (
	ipmiServer   *server.Server
	ipmiServerMu sync.Mutex
)

// initIPMI starts the IPMI server when it is enabled in config. It is off by
// default: see the credential note on Config.EncryptedPassword and the header
// of credentials.go for why enabling it is a decision rather than a default.
func initIPMI() error {
	// BMC mode is the precondition: without it the USB functions IPMI manages
	// over are not guaranteed to be present, and a listener that answers but
	// cannot reach the host is worse than no listener.
	if !bmcModeEnabled() {
		ipmiLogger.Debug().Msg("Board Management Controller mode is disabled; not starting IPMI")
		return nil
	}
	if !config.IPMIEnabled {
		ipmiLogger.Debug().Msg("IPMI is disabled")
		return nil
	}

	// The device password, shared with the web UI and Redfish. RAKP needs the
	// bytes rather than a hash, which is why credentials.go stores a sealed
	// copy alongside the bcrypt one; refuse to start rather than fall back to
	// anything weaker.
	password, err := sharedPasswordForIPMI()
	if err != nil {
		return fmt.Errorf("IPMI credential unavailable: %w", err)
	}

	b, err := newIPMIBMC(ipmiUsername, password)
	if err != nil {
		return fmt.Errorf("build BMC: %w", err)
	}

	addr := fmt.Sprintf(":%d", ipmiPort)
	conn, err := udp.Listen(addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	// NewServer builds its own registry and offers no way to add to it after the
	// fact, so the standard handlers are registered here and the SOL payload
	// commands alongside them.
	reg := handlers.NewRegistry()
	handlers.RegisterAppHandlers(reg)
	handlers.RegisterSessionHandlers(reg)
	handlers.RegisterChassisHandlers(reg)
	handlers.RegisterStorageHandlers(reg)
	solRegisterHandlers(reg)

	srv := server.NewServer(b, newSOLConn(conn, b),
		server.WithHandlerRegistry(reg),
		server.WithCipherSuites(ipmiCipherSuites),
		// IPMI v1.5 sessions authenticate with a straight MD5 (or worse, MD2,
		// plaintext, or none) over the password. RMCP+ is not strong, but v1.5
		// is materially weaker, and anything speaking to this BMC can speak
		// v2.0. Refusing v1.5 costs nothing and removes the weakest path in.
		server.WithV15Disabled(),
	)

	ipmiServerMu.Lock()
	ipmiServer = srv
	ipmiServerMu.Unlock()

	go func() {
		defer conn.Close()
		ipmiLogger.Info().
			Int("port", ipmiPort).
			Str("user", ipmiUsername).
			Msg("IPMI server listening")
		if err := srv.Serve(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
			ipmiLogger.Error().Err(err).Msg("IPMI server stopped")
		}
	}()

	return nil
}

// stopIPMI shuts the server down. Safe to call when it was never started.
func stopIPMI() {
	ipmiServerMu.Lock()
	srv := ipmiServer
	ipmiServer = nil
	ipmiServerMu.Unlock()

	// Before closing the socket: an active console still holds a subscription to
	// the serial broker, and the broker only closes the tty when the last
	// subscriber leaves.
	solShutdown()

	if srv != nil {
		srv.Close()
	}
}

// newIPMIBMC assembles the BMC with this device's identity and a single
// administrator account on the LAN channel.
func newIPMIBMC(username, password string) (*bmc.BMC, error) {
	info := bmc.DeviceInfo{
		DeviceID:       0x20,
		DeviceRevision: 1,
		FirmwareMajor:  1,
		FirmwareMinor:  0,
		// IPMI 2.0. The nibbles are the other way round from the obvious
		// reading: v2.0 Table 20-2 puts the *most* significant BCD digit in bits
		// 3:0 and the least significant in bits 7:4, which is why the spec's own
		// example gives 51h for version 1.5. 0x20 is therefore version 0.2, and
		// ipmitool duly prints "IPMI Version : 0.2" for it. go-ipmi's own
		// reference server and tests use 0x20; they are wrong.
		IPMIVersion: 0x02,
		// No IANA Enterprise Number is registered for JetKVM, and inventing one
		// would collide with whoever holds it. 0 is the "unspecified" value and
		// is what an unregistered implementation should report.
		ManufacturerID: 0,
		ProductID:      0,
		// Chassis device + FRU inventory. Deliberately no sensor, SDR, SEL or
		// IPMB bits: claiming them would make clients ask for data this BMC
		// cannot produce.
		AdditionalDeviceSupport: 0x88,
	}

	b := bmc.New(info, ipmiDeviceGUID(), newJetKVMHAL())

	user, err := b.Users.Add(ipmiUserSlot, username)
	if err != nil {
		return nil, fmt.Errorf("add user: %w", err)
	}
	user.SetPassword([]byte(password))
	user.Enabled = true
	user.ChannelAccess[ipmiChannel] = bmc.UserChannelAccess{
		MaxPrivilege: bmc.PrivilegeLevelAdministrator,
		Enabled:      true,
	}

	return b, nil
}

// ipmiDeviceGUID derives the BMC's GUID from this device's ID so it is stable
// across restarts and distinct between units, which is what clients that cache
// a BMC by GUID expect.
func ipmiDeviceGUID() [16]byte {
	var guid [16]byte
	copy(guid[:], GetDeviceID())
	return guid
}

// --- HAL --------------------------------------------------------------------

// jetkvmHAL is the top-level hardware abstraction. Only the subsystems this
// device can actually answer for are non-nil; see the file comment for why the
// others are absent.
type jetkvmHAL struct {
	chassis hal.ChassisHAL
	storage hal.StorageHAL
}

func newJetKVMHAL() *jetkvmHAL {
	return &jetkvmHAL{
		chassis: &jetkvmChassis{},
		storage: &jetkvmStorage{},
	}
}

func (h *jetkvmHAL) Chassis() hal.ChassisHAL { return h.chassis }
func (h *jetkvmHAL) Storage() hal.StorageHAL { return h.storage }
func (h *jetkvmHAL) Sensors() hal.SensorHAL  { return nil }
func (h *jetkvmHAL) Network() hal.NetworkHAL { return nil }
func (h *jetkvmHAL) GPIO() hal.GPIOHAL       { return nil }
func (h *jetkvmHAL) I2C() hal.I2CHAL         { return nil }
func (h *jetkvmHAL) Close() error            { return nil }

// jetkvmChassis implements power and boot control on top of the same functions
// the Redfish handlers use. It holds no state of its own: power lives in the
// extension, boot override lives in redfishHost.
type jetkvmChassis struct{}

// PowerState reports whether the managed host is on.
//
// redfishPowerState returns "" when no power extension is loaded, which is a
// third answer -- "this BMC cannot see the host's power" -- that the IPMI
// interface has no way to express. Reporting it as "off" would be a guess that
// looks like a measurement, so it is an error instead.
func (c *jetkvmChassis) PowerState(_ context.Context) (bool, error) {
	switch redfishPowerState() {
	case "On":
		return true, nil
	case "Off":
		return false, nil
	default:
		return false, fmt.Errorf("no power-control extension is active")
	}
}

func (c *jetkvmChassis) SetPower(_ context.Context, on bool) error {
	if on {
		return ipmiResetResult(performRedfishReset("On"))
	}
	return ipmiResetResult(performRedfishReset("ForceOff"))
}

func (c *jetkvmChassis) PowerCycle(_ context.Context) error {
	return ipmiResetResult(performRedfishReset("PowerCycle"))
}

func (c *jetkvmChassis) ColdReset(_ context.Context) error {
	return ipmiResetResult(performRedfishReset("ForceRestart"))
}

// WarmReset asks the OS to reboot itself. Only the ATX extension can do that,
// via the power button's graceful path; the DC extension can only cut the rail,
// which is a cold reset by another name. Callers get ErrNotSupported rather
// than a cold reset dressed up as a warm one -- a warm reset that silently
// power-cycles is how an orderly shutdown turns into a lost filesystem.
func (c *jetkvmChassis) WarmReset(_ context.Context) error {
	for _, t := range redfishAllowableResetTypes() {
		if t == "GracefulRestart" {
			return ipmiResetResult(performRedfishReset("GracefulRestart"))
		}
	}
	return hal.ErrNotSupported
}

// Identify would pulse the *managed system's* front-panel LED. This BMC has no
// connection to one -- it drives power and reads video, and neither carries a
// chassis identify signal.
func (c *jetkvmChassis) Identify(_ context.Context, _ uint8) error {
	return hal.ErrNotSupported
}

// IntrusionState needs a chassis intrusion switch, which nothing here is wired
// to.
func (c *jetkvmChassis) IntrusionState(_ context.Context) (bool, error) {
	return false, hal.ErrNotSupported
}

// SetBootFlags stages a boot override for the host's next boot.
//
// This writes the same two fields a Redfish PATCH of Boot writes, because the
// host's firmware reads exactly those on its next boot and knows nothing about
// IPMI. "ipmitool chassis bootdev pxe" and a Redfish BootSourceOverrideTarget
// PATCH are therefore the same operation reached two ways, and the acknowledge
// handshake -- firmware clears the override once it has armed BootNext -- is
// unchanged.
//
// Selectors the firmware cannot act on are refused rather than accepted and
// dropped. An override that silently does nothing is worse than one that fails,
// because the failure is discovered at the next boot instead of at the command.
func (c *jetkvmChassis) SetBootFlags(_ context.Context, flags *types.BootOptionParam_BootFlags) error {
	if flags == nil {
		return fmt.Errorf("nil boot flags")
	}

	target := "None"
	enabled := "Disabled"

	if flags.BootFlagsValid {
		mapped, ok := ipmiBootTarget(flags.BootDeviceSelector)
		if !ok {
			return hal.ErrNotSupported
		}
		target = mapped
		if target != "None" {
			// IPMI's persist bit and Redfish's Continuous/Once are the same
			// distinction: apply to every boot, or consume on the next one.
			enabled = "Once"
			if flags.Persist {
				enabled = "Continuous"
			}
		}
	}

	// Through the shared setter, which also persists: "ipmitool chassis bootdev
	// pxe" is expected to survive a BMC reset, and v2.0 §28.13's rules for when
	// boot flags get cleared only make sense for flags that otherwise stay put.
	redfishSetBootOverride(target, enabled)

	ipmiLogger.Info().
		Str("target", target).
		Str("enabled", enabled).
		Msg("boot override staged over IPMI")

	return nil
}

// GetBootFlags reads back what SetBootFlags (or a Redfish PATCH) staged.
func (c *jetkvmChassis) GetBootFlags(_ context.Context) (*types.BootOptionParam_BootFlags, error) {
	redfishHostMu.RLock()
	target := redfishHost.BootOverrideTarget
	enabled := redfishHost.BootOverrideEnabled
	redfishHostMu.RUnlock()

	flags := &types.BootOptionParam_BootFlags{
		// The managed host boots UEFI; saying "PC compatible" would misdescribe
		// what the firmware does with the selector.
		BIOSBootType: types.BIOSBootTypeEFI,
	}

	if enabled != "Disabled" && target != "None" {
		flags.BootFlagsValid = true
		flags.Persist = enabled == "Continuous"
		flags.BootDeviceSelector = ipmiBootSelector(target)
	}

	return flags, nil
}

// SetBootInfoAcknowledge records which party consumed the boot flags. Nothing
// here acts on that, and hal documents a no-op as the correct response.
func (c *jetkvmChassis) SetBootInfoAcknowledge(_ context.Context, _ *types.BootOptionParam_BootInfoAcknowledge) error {
	return nil
}

func (c *jetkvmChassis) GetBootInfoAcknowledge(_ context.Context) (*types.BootOptionParam_BootInfoAcknowledge, error) {
	return nil, hal.ErrNotSupported
}

// ipmiBootTarget maps an IPMI boot device selector onto the Redfish
// BootSourceOverrideTarget the host firmware understands. The false return is
// "this platform has no such boot option", not "unknown selector".
//
// Only the four in redfishBootOverrideTargets are mappable, and that list is
// itself constrained by what the firmware implements. Diagnostic partition,
// remote media and floppy have no counterpart on this host.
func ipmiBootTarget(sel types.BootDeviceSelector) (string, bool) {
	switch sel {
	case types.BootDeviceSelectorNoOverride:
		return "None", true
	case types.BootDeviceSelectorForcePXE:
		return "Pxe", true
	case types.BootDeviceSelectorForceHardDrive:
		return "Hdd", true
	case types.BootDeviceSelectorForceBIOSSetup:
		return "BiosSetup", true
	default:
		return "", false
	}
}

// ipmiBootSelector is the inverse of ipmiBootTarget.
func ipmiBootSelector(target string) types.BootDeviceSelector {
	switch target {
	case "Pxe":
		return types.BootDeviceSelectorForcePXE
	case "Hdd":
		return types.BootDeviceSelectorForceHardDrive
	case "BiosSetup":
		return types.BootDeviceSelectorForceBIOSSetup
	default:
		return types.BootDeviceSelectorNoOverride
	}
}

// ipmiResetResult discards the HTTP status performRedfishReset returns for its
// Redfish callers and keeps the error.
func ipmiResetResult(_ int, err error) error {
	return err
}

// --- FRU --------------------------------------------------------------------

// jetkvmStorage exposes FRU inventory. SDR is nil: with no sensors there are no
// sensor data records to describe.
type jetkvmStorage struct{}

func (s *jetkvmStorage) FRU() hal.FRUStore { return &jetkvmFRUStore{} }
func (s *jetkvmStorage) SDR() hal.SDRStore { return nil }

// jetkvmFRUStore serves the managed host's identity as FRU inventory.
//
// The data is real: the host's firmware reports its SMBIOS type 1 manufacturer,
// model and serial over the Redfish host interface on every boot, and this
// hands the same values back. "ipmitool fru" therefore names the actual machine
// rather than the BMC or a placeholder.
//
// It is generated per read rather than cached because the underlying state is
// itself per-boot -- a host that has not reported yet has no identity to give,
// and a host that was replaced reports a different one.
type jetkvmFRUStore struct{}

// ipmiFRUDeviceID is the builtin management-controller FRU, the one clients
// read by default.
const ipmiFRUDeviceID uint8 = 0

func (f *jetkvmFRUStore) Read(_ context.Context, deviceID uint8) ([]byte, error) {
	if deviceID != ipmiFRUDeviceID {
		return nil, hal.ErrNotFound
	}

	redfishHostMu.RLock()
	manufacturer := redfishHost.Manufacturer
	model := redfishHost.Model
	serial := redfishHost.SerialNumber
	version := redfishHost.BiosVersion
	redfishHostMu.RUnlock()

	// Before the host's first report there is nothing to describe. An empty
	// FRU would read as "this machine has no identity" rather than "it has not
	// said yet", so name the BMC instead -- which is what is actually answering.
	if manufacturer == "" && model == "" && serial == "" {
		manufacturer = "JetKVM"
		model = "JetKVM Managed System"
		serial = GetDeviceID()
		version = ""
	}

	data, err := types.PackFRU(types.FRUPackConfig{
		Product: &types.FRUPackProduct{
			Manufacturer: manufacturer,
			Name:         model,
			Serial:       serial,
			Version:      version,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("pack FRU: %w", err)
	}
	return data, nil
}

// Write is refused: this FRU is a view of the host's own SMBIOS data, so a
// write would either be silently discarded on the next boot or would overwrite
// a measurement with an assertion.
func (f *jetkvmFRUStore) Write(_ context.Context, _ uint8, _ []byte) error {
	return hal.ErrNotSupported
}

func (f *jetkvmFRUStore) Delete(_ context.Context, _ uint8) error {
	return hal.ErrNotSupported
}

func (f *jetkvmFRUStore) DeviceIDs(_ context.Context) ([]uint8, error) {
	return []uint8{ipmiFRUDeviceID}, nil
}

// --- config validation ------------------------------------------------------

// validateIPMIConfig reports why an IPMI configuration would be refused, so the
// caller can reject it at the point of change rather than at the next restart.
// The enable bit is the whole IPMI configuration -- port, channel and username
// are fixed (see the constants above) -- so the one thing left to check is that
// the shared credential exists.
func validateIPMIConfig(c *Config) error {
	if c.IPMIEnabled && c.EncryptedPassword == "" {
		return fmt.Errorf("IPMI requires a device password; set one with Board Management Controller mode enabled")
	}
	return nil
}

// ipmiRestart applies a configuration change without a reboot.
func ipmiRestart() error {
	stopIPMI()
	// The listener is closed asynchronously by the serve goroutine; give it a
	// moment to release the port before rebinding it.
	time.Sleep(100 * time.Millisecond)
	return initIPMI()
}
