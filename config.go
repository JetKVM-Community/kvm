package kvm

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jetkvm/kvm/internal/confparser"
	"github.com/jetkvm/kvm/internal/logging"
	"github.com/jetkvm/kvm/internal/native"
	"github.com/jetkvm/kvm/internal/network/types"
	"github.com/jetkvm/kvm/internal/sync"
	"github.com/jetkvm/kvm/internal/usbgadget"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	DefaultAPIURL = "https://api.jetkvm.com"
)

type WakeOnLanDevice struct {
	Name        string `json:"name"`
	MacAddress  string `json:"macAddress"`
	BroadcastIP string `json:"broadcastIP,omitempty"`
}

// Constants for keyboard macro limits
const (
	MaxMacrosPerDevice = 25
	MaxStepsPerMacro   = 10
	MaxKeysPerStep     = 10
	MinStepDelay       = 50
	MaxStepDelay       = 2000
)

type KeyboardMacroStep struct {
	Keys      []string `json:"keys"`
	Modifiers []string `json:"modifiers"`
	Delay     int      `json:"delay"`
}

func (s *KeyboardMacroStep) Validate() error {
	if len(s.Keys) > MaxKeysPerStep {
		return fmt.Errorf("too many keys in step (max %d)", MaxKeysPerStep)
	}

	if s.Delay < MinStepDelay {
		s.Delay = MinStepDelay
	} else if s.Delay > MaxStepDelay {
		s.Delay = MaxStepDelay
	}

	return nil
}

type KeyboardMacro struct {
	ID        string              `json:"id"`
	Name      string              `json:"name"`
	Steps     []KeyboardMacroStep `json:"steps"`
	SortOrder int                 `json:"sortOrder,omitempty"`
}

func (m *KeyboardMacro) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("macro name cannot be empty")
	}

	if len(m.Steps) == 0 {
		return fmt.Errorf("macro must have at least one step")
	}

	if len(m.Steps) > MaxStepsPerMacro {
		return fmt.Errorf("too many steps in macro (max %d)", MaxStepsPerMacro)
	}

	for i := range m.Steps {
		if err := m.Steps[i].Validate(); err != nil {
			return fmt.Errorf("invalid step %d: %w", i+1, err)
		}
	}

	return nil
}

type Config struct {
	CloudURL             string               `json:"cloud_url"`
	UpdateAPIURL         string               `json:"update_api_url"`
	CloudAppURL          string               `json:"cloud_app_url"`
	CloudToken           string               `json:"cloud_token"`
	TailscaleControlURL  string               `json:"tailscale_control_url,omitempty"`
	GoogleIdentity       string               `json:"google_identity"`
	JigglerEnabled       bool                 `json:"jiggler_enabled"`
	JigglerConfig        *JigglerConfig       `json:"jiggler_config"`
	AutoUpdateEnabled    bool                 `json:"auto_update_enabled"`
	IncludePreRelease    bool                 `json:"include_pre_release"`
	HashedPassword       string               `json:"hashed_password"`
	LocalAuthToken       string               `json:"local_auth_token"`
	LocalAuthMode        string               `json:"localAuthMode"` //TODO: fix it with migration
	LocalLoopbackOnly    bool                 `json:"local_loopback_only"`
	WakeOnLanDevices     []WakeOnLanDevice    `json:"wake_on_lan_devices"`
	KeyboardMacros       []KeyboardMacro      `json:"keyboard_macros"`
	KeyboardLayout       string               `json:"keyboard_layout"`
	EdidString           string               `json:"hdmi_edid_string"`
	ActiveExtension      string               `json:"active_extension"`
	DisplayRotation      string               `json:"display_rotation"`
	DisplayMaxBrightness int                  `json:"display_max_brightness"`
	DisplayDimAfterSec   int                  `json:"display_dim_after_sec"`
	DisplayOffAfterSec   int                  `json:"display_off_after_sec"`
	TLSMode              string               `json:"tls_mode"` // options: "self-signed", "user-defined", ""
	UsbConfig            *usbgadget.Config    `json:"usb_config"`
	UsbDevices           *usbgadget.Devices   `json:"usb_devices"`
	NetworkConfig        *types.NetworkConfig `json:"network_config"`
	DefaultLogLevel      string               `json:"default_log_level"`
	VideoSleepAfterSec   int                  `json:"video_sleep_after_sec"`
	VideoQualityFactor   float64              `json:"video_quality_factor"`
	VideoCodecPreference string               `json:"video_codec_preference"`
	HideDisplayWhenIdle  bool                 `json:"host_display_disable_when_idle"`
	NativeMaxRestart     uint                 `json:"native_max_restart_attempts"`
	MqttConfig           *MQTTConfig          `json:"mqtt_config"`
	AudioEnabled         bool                 `json:"audio_enabled"`

	// BmcEnabled turns this device into a baseboard management controller for
	// the attached host: it is what gates Redfish and IPMI, and it pins the USB
	// gadget to the function set those protocols depend on.
	//
	// The pinning is the point. Out-of-band management is not a feature of the
	// BMC alone -- it is a property of the USB link. Redfish reaches the host's
	// firmware over CDC-ECM, virtual media over mass storage, and a serial
	// console over CDC-ACM. Unticking one of those in the USB class editor would
	// silently remove a management path that an operator is relying on, and the
	// symptom would appear a boot later and somewhere else. So while this is on,
	// the class selection is locked to the BMC set; turning it off unlocks it.
	BmcEnabled bool `json:"bmc_enabled"`

	// IPMI 2.0 over RMCP+ (see ipmi.go). Requires BmcEnabled. Off by default,
	// and worth leaving off unless something actually needs it.
	//
	// IPMIPassword is stored in the clear, and cannot be anything else: RMCP+
	// authenticates by having both ends compute an HMAC over the password
	// itself (v2.0 RAKP), so the BMC needs the original bytes on every session
	// open. It is a distinct credential from HashedPassword on purpose --
	// enabling IPMI must not put the web UI's password on disk in plaintext.
	//
	// Note also that RAKP hands an HMAC of that password to anyone who asks for
	// a session, without authenticating them first, which makes it offline
	// crackable. That is a property of the protocol rather than of this
	// implementation and cannot be fixed here; it is the reason the default is
	// off and the reason to prefer a long random value.
	IPMIEnabled  bool   `json:"ipmi_enabled"`
	IPMIPort     int    `json:"ipmi_port"`
	IPMIUsername string `json:"ipmi_username"`
	IPMIPassword string `json:"ipmi_password"`

	// A boot override staged for the managed host, over either Redfish or IPMI.
	//
	// This is the one piece of the host-facing state that is persisted, and the
	// distinction is what it is rather than how much it matters. Everything else
	// the host reports -- identity, BIOS attributes, boot options, memory,
	// drives -- is an *observation* of the machine currently running, and a copy
	// of it surviving a BMC restart would assert something the BMC no longer
	// knows. An override is an *instruction*: an operator said "boot this next
	// time", and the host has not read it yet. Dropping it on a restart loses
	// the instruction silently, and the operator finds out by watching the wrong
	// thing boot.
	//
	// IPMI makes this concrete. "ipmitool chassis bootdev pxe" is expected to
	// survive a BMC reset -- v2.0 §28.13 gives boot parameter 3 a whole set of
	// rules for when flags get cleared, which only makes sense for flags that
	// otherwise persist.
	HostBootOverrideTarget  string `json:"host_boot_override_target"`
	HostBootOverrideEnabled string `json:"host_boot_override_enabled"`
}

// GetUpdateAPIURL returns the update API URL
func (c *Config) GetUpdateAPIURL() string {
	if c.UpdateAPIURL == "" {
		return DefaultAPIURL
	}
	return strings.TrimSuffix(c.UpdateAPIURL, "/") + "/releases"
}

// GetDisplayRotation returns the display rotation
func (c *Config) GetDisplayRotation() uint16 {
	rotationInt, err := strconv.ParseUint(c.DisplayRotation, 10, 16)
	if err != nil {
		logger.Warn().Err(err).Msg("invalid display rotation, using default")
		return 270
	}
	return uint16(rotationInt)
}

// SetDisplayRotation sets the display rotation
func (c *Config) SetDisplayRotation(rotation string) error {
	_, err := strconv.ParseUint(rotation, 10, 16)
	if err != nil {
		logger.Warn().Err(err).Msg("invalid display rotation, using default")
		return err
	}
	c.DisplayRotation = rotation
	return nil
}

// configPath is a var rather than a const so tests can redirect it. The device
// test suite runs *on the device*, against the real filesystem: a test that
// installs a fixture config and triggers a save would otherwise overwrite the
// operator's real one -- password, cloud token and all.
var configPath = "/userdata/kvm_config.json"

// it's a temporary solution to avoid sharing the same pointer
// we should migrate to a proper config solution in the future
var (
	defaultJigglerConfig = JigglerConfig{
		InactivityLimitSeconds: 60,
		JitterPercentage:       25,
		ScheduleCronTab:        "0 * * * * *",
		Timezone:               "UTC",
	}
	defaultUsbConfig = usbgadget.Config{
		VendorId:     "0x1d6b", //The Linux Foundation
		ProductId:    "0x0104", //Multifunction Composite Gadget
		SerialNumber: "",
		Manufacturer: "JetKVM",
		Product:      "USB Emulation Device",
	}
	defaultUsbDevices = usbgadget.Devices{
		AbsoluteMouse: true,
		RelativeMouse: true,
		Keyboard:      true,
		MassStorage:   true,
		Audio:         true,
		// Ethernet (CDC-ECM) is opt-in, but NOT because it conflicts with
		// anything: it changes what the attached host sees (an extra NIC), so
		// it should be a deliberate choice.
		//
		// An earlier version of this comment claimed the ECM bulk-IN endpoint
		// could not share the RV1106 dwc3 TxFIFO RAM with mass storage's, and
		// that enabling both broke enumeration and the HID keyboard. That does
		// not reproduce on the current firmware. Measured on hardware
		// 2026-07-29 with ecm.usb0 + mass_storage.usb0 + 4x hid + uac1 bound
		// simultaneously (9 USB interfaces, 8 IN endpoints of NUM_IN_EPS=10):
		// the UDC reached "configured", the host bound cdc_ether and pinged
		// over usb0 at 0.2-0.4 ms with no loss, "JetKVM Virtual Media" still
		// attached as sr0, and the HID mice/keyboard still enumerated. dwc3
		// reallocated the TxFIFOs on the fly (tx-fifo-resize is set in the DT),
		// which is exactly what it is supposed to do.
		Ethernet: false,
	}
)

func getDefaultConfig() Config {
	return Config{
		CloudURL:          DefaultAPIURL,
		UpdateAPIURL:      DefaultAPIURL,
		CloudAppURL:       "https://app.jetkvm.com",
		AutoUpdateEnabled: true, // Set a default value
		ActiveExtension:   "",
		IPMIEnabled:       false,
		IPMIPort:          ipmiDefaultPort,
		// No override staged. These mirror the Redfish vocabulary because that
		// is what the host firmware reads; the IPMI side translates.
		HostBootOverrideTarget:  "None",
		HostBootOverrideEnabled: "Disabled",
		KeyboardMacros:          []KeyboardMacro{},
		DisplayRotation:         "270",
		KeyboardLayout:          "en-US",
		DisplayMaxBrightness:    64,
		DisplayDimAfterSec:      120,  // 2 minutes
		DisplayOffAfterSec:      1800, // 30 minutes
		JigglerEnabled:          false,
		// This is the "Standard" jiggler option in the UI
		JigglerConfig: func() *JigglerConfig { c := defaultJigglerConfig; return &c }(),
		TLSMode:       "",
		UsbConfig:     func() *usbgadget.Config { c := defaultUsbConfig; return &c }(),
		UsbDevices:    func() *usbgadget.Devices { c := defaultUsbDevices; return &c }(),
		NetworkConfig: func() *types.NetworkConfig {
			c := &types.NetworkConfig{}
			_ = confparser.SetDefaultsAndValidate(c)
			return c
		}(),
		DefaultLogLevel:      "WARN",
		VideoQualityFactor:   1.0,
		VideoCodecPreference: "auto",
		MqttConfig: &MQTTConfig{
			Enabled:           false,
			Port:              1883,
			BaseTopic:         "jetkvm",
			EnableHADiscovery: false,
			EnableActions:     true,
			DebounceMs:        500,
		},
	}
}

var (
	config     *Config
	configLock = &sync.Mutex{}
)

var (
	configSuccess = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "jetkvm_config_last_reload_successful",
			Help: "The last configuration load succeeded",
		},
	)
	configSuccessTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "jetkvm_config_last_reload_success_timestamp_seconds",
			Help: "Timestamp of last successful config load",
		},
	)
)

func LoadConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	if config != nil {
		logger.Debug().Msg("config already loaded, skipping")
		return
	}

	// load the default config
	defaultConfig := getDefaultConfig()
	config = &defaultConfig

	file, err := os.Open(configPath)
	if err != nil {
		logger.Debug().Msg("default config file doesn't exist, using default")
		configSuccess.Set(1.0)
		configSuccessTime.SetToCurrentTime()
		return
	}
	defer file.Close()

	// load and merge the default config with the user config
	rawConfig, err := io.ReadAll(file)
	if err != nil {
		logger.Warn().Err(err).Msg("config file reading failed")
		configSuccess.Set(0.0)
		return
	}

	loadedConfig := defaultConfig
	if err := json.Unmarshal(rawConfig, &loadedConfig); err != nil {
		logger.Warn().Err(err).Msg("config file JSON parsing failed")
		configSuccess.Set(0.0)
		return
	}

	// merge the user config with the default config
	if loadedConfig.UsbConfig == nil {
		loadedConfig.UsbConfig = getDefaultConfig().UsbConfig
	}

	if loadedConfig.UsbDevices == nil {
		loadedConfig.UsbDevices = getDefaultConfig().UsbDevices
	} else if !usbDevicesConfigHasAudio(rawConfig) {
		loadedConfig.UsbDevices.Audio = defaultUsbDevices.Audio
	}

	if !loadedConfig.UsbDevices.Audio {
		loadedConfig.AudioEnabled = false
	}

	if loadedConfig.NetworkConfig == nil {
		loadedConfig.NetworkConfig = getDefaultConfig().NetworkConfig
	}

	if loadedConfig.JigglerConfig == nil {
		loadedConfig.JigglerConfig = getDefaultConfig().JigglerConfig
	}

	if loadedConfig.MqttConfig == nil {
		loadedConfig.MqttConfig = getDefaultConfig().MqttConfig
	}

	// fixup old keyboard layout value
	if loadedConfig.KeyboardLayout == "en_US" {
		loadedConfig.KeyboardLayout = "en-US"
	}

	// Until rolling logs land, do not persist verbose levels across reboots.
	loadedConfig.DefaultLogLevel = "WARN"

	// Migrate prior JetKVM defaults to the current native.DefaultEDID:
	//   - Toshiba TSB chip default (pre-JetKVM-v1 EDID, no CEA extension)
	//   - JetKVM v1 EDID without the 1280x720@120 DTD (the previous default that
	//     advertised only 1080p60 + 720p60 in the base block)
	//   - JetKVM v1 EDID with 720p120 in CTA extension only (NVIDIA didn't pick
	//     it up; superseded by base-block DTD1 = 720p120)
	const tsbDefaultEDID = "00ffffffffffff0052620188008888881c150103800000780a0dc9a05747982712484c00000001010101010101010101010101010101023a801871382d40582c4500c48e2100001e011d007251d01e206e285500c48e2100001e000000fc00543734392d6648443732300a20000000fd00147801ff1d000a202020202020017b"
	const jkvV1NoHighRefresh = "00ffffffffffff0028b4010001eeffc0302301038047287856ee91a3544c99260f5054000000d1c081c0318001010101010101010101023a801871382d40582c4500c48e2100001e011d007251d01e206e285500c48e2100001e000000fd00174c0f5111000a202020202020000000fc004a65744b564d2076310a202020011d020322d1431004012309070783010000e200cfe40d100401e305000065030c001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cf"
	const jkvV1CtaOnly120 = "00ffffffffffff0028b4010001eeffc0302301038047287856ee91a3544c99260f5054000000d1c081c0318001010101010101010101023a801871382d40582c4500c48e2100001e011d007251d01e206e285500c48e2100001e000000fd00174c0f5111000a202020202020000000fc004a65744b564d2076310a202020011d020322d1431004012309070783010000e200cfe40d100401e305000065030c001000773300a050d02b2030203500122c2100001a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c"
	if loadedConfig.EdidString == "" ||
		strings.EqualFold(loadedConfig.EdidString, tsbDefaultEDID) ||
		strings.EqualFold(loadedConfig.EdidString, jkvV1NoHighRefresh) ||
		strings.EqualFold(loadedConfig.EdidString, jkvV1CtaOnly120) {
		loadedConfig.EdidString = native.DefaultEDID
	}

	config = &loadedConfig

	logging.GetRootLogger().UpdateLogLevel(config.DefaultLogLevel)

	configSuccess.Set(1.0)
	configSuccessTime.SetToCurrentTime()

	logger.Info().Str("path", configPath).Msg("config loaded")
}

func usbDevicesConfigHasAudio(rawConfig []byte) bool {
	var payload struct {
		UsbDevices map[string]json.RawMessage `json:"usb_devices"`
	}

	if err := json.Unmarshal(rawConfig, &payload); err != nil || payload.UsbDevices == nil {
		return true
	}

	_, ok := payload.UsbDevices["audio"]
	return ok
}

func SaveConfig() error {
	return saveConfig(configPath)
}

func SaveBackupConfig() error {
	return saveConfig(configPath + ".bak")
}

func saveConfig(path string) error {
	configLock.Lock()
	defer configLock.Unlock()

	logger.Trace().Str("path", path).Msg("Saving config")

	// fixup old keyboard layout value
	if config.KeyboardLayout == "en_US" {
		config.KeyboardLayout = "en-US"
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to wite config: %w", err)
	}

	logger.Info().Str("path", path).Msg("config saved")
	return nil
}

func ensureConfigLoaded() {
	if config == nil {
		LoadConfig()
	}
}
