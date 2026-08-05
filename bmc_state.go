package kvm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jetkvm/kvm/internal/sync"
)

// On-disk persistence for everything the managed host reports and everything an
// operator stages for it, so both survive a reboot of this device.
//
// This lives in its own file rather than kvm_config.json for three reasons: it
// is host state rather than device settings and has a different lifecycle; it
// is written on a completely different cadence (a booting host PATCHes and
// POSTs dozens of resources in a couple of seconds, where settings change when
// a person clicks something); and it is far larger -- the BIOS attribute
// registry alone runs to several kilobytes.
//
// A note on staleness, because it is the real hazard here. This data describes
// the machine that was attached when it was captured. After a restart the BMC
// is asserting something it has not re-verified: the host may have been
// replaced, reflashed, or reconfigured while this device was down. Everything
// restored therefore carries CapturedAt, the restore is logged with its age,
// and the host overwrites all of it on its next boot anyway. What persistence
// buys is that an operator querying a powered-off host gets its last known
// inventory instead of an empty collection -- which is the ordinary reason to
// ask.

// Overridable for the same reason as configPath: the device test suite runs
// against the real filesystem.
var bmcStatePath = "/userdata/jetkvm/bmc_state.json"

// bmcStateSaveDelay coalesces the burst of writes a booting host produces. Each
// POSTed boot option or memory module would otherwise be its own rewrite of the
// whole document, on flash.
const bmcStateSaveDelay = 2 * time.Second

// bmcState is the persisted form. It mirrors the in-memory structures rather
// than sharing them: the in-memory ones carry mutexes and are shaped for
// serving, and pinning a disk format to them would make every future field
// rename a migration.
type bmcState struct {
	// CapturedAt is when this snapshot was taken, so a consumer -- or a person
	// reading the file -- can tell how far behind the running host it may be.
	CapturedAt time.Time `json:"captured_at"`

	Host struct {
		BiosVersion  string    `json:"bios_version"`
		Manufacturer string    `json:"manufacturer"`
		Model        string    `json:"model"`
		SerialNumber string    `json:"serial_number"`
		UUID         string    `json:"uuid"`
		BootProgress string    `json:"boot_progress"`
		ReportedAt   time.Time `json:"reported_at"`
	} `json:"host"`

	Client struct {
		BiosAttributes map[string]any            `json:"bios_attributes"`
		BiosPending    map[string]any            `json:"bios_pending"`
		BiosRegistry   map[string]any            `json:"bios_registry,omitempty"`
		BootOptions    map[string]map[string]any `json:"boot_options"`
		Memory         map[string]map[string]any `json:"memory"`
		Drives         map[string]map[string]any `json:"drives"`
		SecureBoot     map[string]any            `json:"secure_boot"`
	} `json:"client"`
}

var (
	bmcStateMu    sync.Mutex
	bmcStateTimer *time.Timer
)

// bmcStateSave schedules a save. Safe to call from any handler; the burst a
// booting host produces collapses into one write.
//
// The boot override is deliberately *not* saved here -- it goes to the config
// file through redfishSetBootOverride, because it is an operator instruction
// rather than host-reported data and must not be lost to a debounce window if
// power is cut in the two seconds after it was staged.
func bmcStateSave() {
	bmcStateMu.Lock()
	defer bmcStateMu.Unlock()

	if bmcStateTimer != nil {
		bmcStateTimer.Stop()
	}
	bmcStateTimer = time.AfterFunc(bmcStateSaveDelay, func() {
		if err := bmcStateWrite(); err != nil {
			redfishLogger.Warn().Err(err).Msg("failed to persist BMC state")
		}
	})
}

// bmcStateFlush writes immediately, for shutdown paths where a pending
// debounced write would otherwise be lost.
func bmcStateFlush() {
	bmcStateMu.Lock()
	if bmcStateTimer != nil {
		bmcStateTimer.Stop()
		bmcStateTimer = nil
	}
	bmcStateMu.Unlock()

	if err := bmcStateWrite(); err != nil {
		redfishLogger.Warn().Err(err).Msg("failed to flush BMC state")
	}
}

func bmcStateSnapshot() *bmcState {
	s := &bmcState{CapturedAt: time.Now()}

	redfishHostMu.RLock()
	s.Host.BiosVersion = redfishHost.BiosVersion
	s.Host.Manufacturer = redfishHost.Manufacturer
	s.Host.Model = redfishHost.Model
	s.Host.SerialNumber = redfishHost.SerialNumber
	s.Host.UUID = redfishHost.UUID
	s.Host.BootProgress = redfishHost.BootProgress
	s.Host.ReportedAt = redfishHost.ReportedAt
	redfishHostMu.RUnlock()

	redfishClient.mu.RLock()
	s.Client.BiosAttributes = redfishCopyMap(redfishClient.BiosAttributes)
	s.Client.BiosPending = redfishCopyMap(redfishClient.BiosPending)
	s.Client.BiosRegistry = redfishCopyMap(redfishClient.BiosRegistry)
	s.Client.BootOptions = bmcCopyResourceMap(redfishClient.BootOptions)
	s.Client.Memory = bmcCopyResourceMap(redfishClient.Memory)
	s.Client.Drives = bmcCopyResourceMap(redfishClient.Drives)
	s.Client.SecureBoot = redfishCopyMap(redfishClient.SecureBoot)
	redfishClient.mu.RUnlock()

	return s
}

func bmcCopyResourceMap(in map[string]map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(in))
	for k, v := range in {
		out[k] = redfishCopyMap(v)
	}
	return out
}

// bmcStateWrite serialises the current state to disk atomically.
//
// Temp file plus rename, because the alternative is a truncated JSON document
// if power is cut mid-write -- and this file is read at boot, so a corrupt one
// would cost the very data it exists to protect.
func bmcStateWrite() error {
	state := bmcStateSnapshot()

	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	dir := filepath.Dir(bmcStatePath)
	tmp, err := os.CreateTemp(dir, ".bmc_state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	// Force the bytes out before the rename; a rename that lands ahead of the
	// data leaves an empty file with a valid name.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, bmcStatePath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// bmcStateLoad restores the last snapshot. Called at startup, before Redfish or
// IPMI can serve anything, so no client observes the gap.
func bmcStateLoad() {
	data, err := os.ReadFile(bmcStatePath)
	if err != nil {
		if !os.IsNotExist(err) {
			redfishLogger.Warn().Err(err).Msg("failed to read persisted BMC state")
		}
		return
	}

	var state bmcState
	if err := json.Unmarshal(data, &state); err != nil {
		// A corrupt file is not worth failing startup over, and it will be
		// replaced by the host's next report.
		redfishLogger.Warn().Err(err).Msg("persisted BMC state is unreadable; ignoring it")
		return
	}

	redfishHostMu.Lock()
	redfishHost.BiosVersion = state.Host.BiosVersion
	redfishHost.Manufacturer = state.Host.Manufacturer
	redfishHost.Model = state.Host.Model
	redfishHost.SerialNumber = state.Host.SerialNumber
	redfishHost.UUID = state.Host.UUID
	redfishHost.BootProgress = state.Host.BootProgress
	redfishHost.ReportedAt = state.Host.ReportedAt
	redfishHostMu.Unlock()

	redfishClient.mu.Lock()
	if state.Client.BiosAttributes != nil {
		redfishClient.BiosAttributes = state.Client.BiosAttributes
	}
	if state.Client.BiosPending != nil {
		redfishClient.BiosPending = state.Client.BiosPending
	}
	// nil stays nil: "the host has not reported a registry" and "the registry is
	// empty" are different answers, and the GET handler distinguishes them.
	redfishClient.BiosRegistry = state.Client.BiosRegistry
	if state.Client.BootOptions != nil {
		redfishClient.BootOptions = state.Client.BootOptions
	}
	if state.Client.Memory != nil {
		redfishClient.Memory = state.Client.Memory
	}
	if state.Client.Drives != nil {
		redfishClient.Drives = state.Client.Drives
	}
	if state.Client.SecureBoot != nil {
		redfishClient.SecureBoot = state.Client.SecureBoot
	}
	counts := [3]int{len(redfishClient.BootOptions), len(redfishClient.Memory), len(redfishClient.Drives)}
	redfishClient.mu.Unlock()

	// Log the age rather than just the fact. This data describes the host as it
	// was, and how long ago that was is the thing a reader needs to judge it.
	age := "unknown"
	if !state.CapturedAt.IsZero() {
		age = time.Since(state.CapturedAt).Round(time.Second).String()
	}
	redfishLogger.Info().
		Str("captured", age+" ago").
		Str("model", state.Host.Model).
		Int("boot_options", counts[0]).
		Int("memory", counts[1]).
		Int("drives", counts[2]).
		Msg("restored persisted BMC state; the host overwrites it on its next boot")
}
