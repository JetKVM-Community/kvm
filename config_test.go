package kvm

import (
	"path/filepath"
	"testing"
)

// withTestConfig installs a fresh default Config for the duration of a test and
// restores whatever was there afterwards.
//
// Two reasons this has to exist rather than tests poking `config` directly:
//
//   - `config` is a *Config that is nil until LoadConfig() runs, and LoadConfig
//     reads a file and touches Prometheus gauges. A test that assigns through
//     the nil pointer panics rather than fails, taking the rest of the package's
//     tests with it.
//   - Saving and restoring the *pointer* does not undo a mutation made through
//     it. Tests that set a field and then "restore" the pointer leave the field
//     set for every test that follows, which makes results depend on run order.
//
// Returning the config lets a caller adjust fields before use.
func withTestConfig(t *testing.T) *Config {
	t.Helper()

	orig := config
	origConfigPath, origStatePath := configPath, bmcStatePath
	t.Cleanup(func() {
		config = orig
		configPath, bmcStatePath = origConfigPath, origStatePath
	})

	// Redirect both on-disk paths. These tests run on the device against the
	// real filesystem, so a save triggered by the code under test would
	// otherwise clobber the operator's actual configuration and host state.
	dir := t.TempDir()
	configPath = filepath.Join(dir, "kvm_config.json")
	bmcStatePath = filepath.Join(dir, "bmc_state.json")

	fresh := getDefaultConfig()
	config = &fresh
	return config
}
