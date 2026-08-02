package kvm

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// Minimal DMTF Redfish (https://www.dmtf.org/standards/redfish) surface for
// out-of-band power control. It exposes a single ComputerSystem whose
// PowerState and ComputerSystem.Reset action are backed by the currently loaded
// power extension ("atx-power" or "dc-power"), driven through the same
// JSON-RPC handlers the WebRTC/HTTP transports use.
//
// Only power control is modeled; this is deliberately a small subset of the
// Redfish schema aimed at orchestrators (Terraform redfish provider, Ansible,
// etc.) that issue ComputerSystem.Reset.

const (
	redfishVersion   = "1.6.0"
	redfishSystemID  = "1"
	redfishManagerID = "bmc"
	redfishChassisID = "1"

	// The USB host interface (DSP0270) link. Requests arriving on this subnet
	// come from the managed host over the point-to-point CDC-ECM link, which is
	// the transport the Redfish Host Interface is defined on.
	redfishHostInterfaceSubnet = "169.254.0.0/16"
)

// redfishUUID renders the device ID as an RFC 4122 UUID string. Redfish
// requires ServiceRoot.UUID to be a real UUID, and EDK2's RedfishDiscoverDxe
// compares it against the UUID in the SMBIOS type 42 protocol record -- a bare
// device ID is rejected. The mapping is deterministic so firmware and BMC agree
// without any exchange.
func redfishUUID() string {
	sum := sha256.Sum256([]byte("jetkvm/redfish-service-uuid/" + GetDeviceID()))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 (name-based)
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// isRedfishHostInterfaceRequest reports whether a request arrived over the USB
// host-interface link rather than the LAN.
func isRedfishHostInterfaceRequest(c *gin.Context) bool {
	ip := net.ParseIP(c.ClientIP())
	if ip == nil {
		return false
	}
	_, subnet, err := net.ParseCIDR(redfishHostInterfaceSubnet)
	if err != nil {
		return false
	}
	return subnet.Contains(ip)
}

// registerRedfishRoutes wires the Redfish endpoints onto the gin engine. The
// unauthenticated protocol-version endpoint lives at /redfish; everything under
// /redfish/v1 requires authentication (HTTP Basic, matching Redfish clients).
func registerRedfishRoutes(r *gin.Engine) {
	// Protocol version discovery (unauthenticated, per Redfish spec).
	r.GET("/redfish", func(c *gin.Context) {
		c.Header("OData-Version", "4.0")
		c.JSON(http.StatusOK, gin.H{"v1": "/redfish/v1/"})
	})

	// Emit the contract at startup. The service UUID must match the one compiled
	// into the firmware's SMBIOS type 42 protocol record
	// (NucRedfishHostInterfaceLib.c) or RedfishDiscoverDxe will refuse to
	// correlate the interface -- and a mismatch is otherwise silent on both
	// sides, so log it where it can be diffed against `cbmem -c`.
	redfishLogger.Info().
		Str("uuid", redfishUUID()).
		Str("host_interface_subnet", redfishHostInterfaceSubnet).
		Str("auth", string(config.LocalAuthMode)).
		Msg("Redfish service registered at /redfish/v1")

	v1 := r.Group("/redfish/v1")
	v1.Use(redfishRequestLogger())
	v1.Use(redfishAuthMiddleware())
	v1.Use(func(c *gin.Context) {
		c.Header("OData-Version", "4.0")
		c.Next()
	})
	{
		v1.GET("/", handleRedfishServiceRoot)
		v1.GET("/Systems", handleRedfishSystemsCollection)
		v1.GET("/Systems/:id", handleRedfishSystem)
		v1.PATCH("/Systems/:id", handleRedfishSystemPatch)
		v1.POST("/Systems/:id/Actions/ComputerSystem.Reset", handleRedfishSystemReset)
		v1.GET("/Managers", handleRedfishManagersCollection)
		v1.GET("/Managers/:id", handleRedfishManager)
		v1.GET("/Chassis", handleRedfishChassisCollection)
		v1.GET("/Chassis/:id", handleRedfishChassis)
		v1.GET("/SessionService", handleRedfishSessionService)
		v1.GET("/SessionService/Sessions", handleRedfishSessions)
	}
}

func handleRedfishManagersCollection(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":         "#ManagerCollection.ManagerCollection",
		"@odata.id":           "/redfish/v1/Managers",
		"Name":                "Manager Collection",
		"Members@odata.count": 1,
		"Members": []gin.H{
			{"@odata.id": "/redfish/v1/Managers/" + redfishManagerID},
		},
	})
}

func handleRedfishManager(c *gin.Context) {
	if c.Param("id") != redfishManagerID {
		redfishError(c, http.StatusNotFound, "Manager not found")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"@odata.type":     "#Manager.v1_5_0.Manager",
		"@odata.id":       "/redfish/v1/Managers/" + redfishManagerID,
		"Id":              redfishManagerID,
		"Name":            "JetKVM BMC",
		"ManagerType":     "BMC",
		"UUID":            redfishUUID(),
		"Model":           "JetKVM",
		"FirmwareVersion": builtAppVersion,
		"PowerState":      "On",
		"Status":          gin.H{"State": "Enabled", "Health": "OK"},
		"Links": gin.H{
			"ManagerForServers": []gin.H{
				{"@odata.id": "/redfish/v1/Systems/" + redfishSystemID},
			},
			"ManagerForChassis": []gin.H{
				{"@odata.id": "/redfish/v1/Chassis/" + redfishChassisID},
			},
		},
	})
}

func handleRedfishChassisCollection(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":         "#ChassisCollection.ChassisCollection",
		"@odata.id":           "/redfish/v1/Chassis",
		"Name":                "Chassis Collection",
		"Members@odata.count": 1,
		"Members": []gin.H{
			{"@odata.id": "/redfish/v1/Chassis/" + redfishChassisID},
		},
	})
}

func handleRedfishChassis(c *gin.Context) {
	if c.Param("id") != redfishChassisID {
		redfishError(c, http.StatusNotFound, "Chassis not found")
		return
	}

	chassis := gin.H{
		"@odata.type":  "#Chassis.v1_10_0.Chassis",
		"@odata.id":    "/redfish/v1/Chassis/" + redfishChassisID,
		"Id":           redfishChassisID,
		"Name":         "Managed Chassis",
		"ChassisType":  "RackMount",
		"Manufacturer": "JetKVM",
		"Status":       gin.H{"State": "Enabled", "Health": "OK"},
		"Links": gin.H{
			"ComputerSystems": []gin.H{
				{"@odata.id": "/redfish/v1/Systems/" + redfishSystemID},
			},
			"ManagedBy": []gin.H{
				{"@odata.id": "/redfish/v1/Managers/" + redfishManagerID},
			},
		},
	}

	if state := redfishPowerState(); state != "" {
		chassis["PowerState"] = state
	}

	c.JSON(http.StatusOK, chassis)
}

// SessionService is advertised but sessions are not implemented: the host
// interface authenticates per-request (Basic, or unauthenticated over the USB
// link). Redfish clients probe this during discovery and treat a well-formed
// empty collection as "use Basic auth".
func handleRedfishSessionService(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":    "#SessionService.v1_1_8.SessionService",
		"@odata.id":      "/redfish/v1/SessionService",
		"Id":             "SessionService",
		"Name":           "Session Service",
		"ServiceEnabled": false,
		"Sessions":       gin.H{"@odata.id": "/redfish/v1/SessionService/Sessions"},
	})
}

func handleRedfishSessions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":         "#SessionCollection.SessionCollection",
		"@odata.id":           "/redfish/v1/SessionService/Sessions",
		"Name":                "Session Collection",
		"Members@odata.count": 0,
		"Members":             []gin.H{},
	})
}

// redfishRequestLogger records every Redfish request before authentication
// runs. gin's own logger reports the result, but not whether the request
// arrived over the USB host interface or the LAN -- which is the distinction
// that decides whether auth is skipped, and the first thing worth knowing when
// firmware-side discovery appears to do nothing.
func redfishRequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		redfishLogger.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Str("client_ip", c.ClientIP()).
			Bool("host_interface", isRedfishHostInterfaceRequest(c)).
			Str("user_agent", c.Request.UserAgent()).
			Msg("Redfish request")
		c.Next()
	}
}

// redfishAuthMiddleware authenticates Redfish requests with HTTP Basic auth
// (any username, the device password). In noPassword mode it is open, matching
// the rest of the local API.
func redfishAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.LocalAuthMode == "noPassword" {
			c.Next()
			return
		}

		// Requests over the USB host interface are unauthenticated. DSP0270
		// permits "no auth" in the host-interface protocol record, and the
		// alternative -- bootstrap credentials -- is delivered over IPMI, which
		// this hardware has no transport for (see the notes in
		// internal/usbgadget/ethernet.go). The boundary this rests on is that
		// usb0 is a point-to-point CDC-ECM link to the one managed host and is
		// not routed: see configureEthernetGadgetInterface() in usb.go, which
		// assigns a link-local address and no gateway.
		if isRedfishHostInterfaceRequest(c) {
			redfishLogger.Debug().
				Str("client_ip", c.ClientIP()).
				Msg("unauthenticated: request arrived over the USB host interface")
			c.Next()
			return
		}

		_, password, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", `Basic realm="JetKVM Redfish"`)
			redfishError(c, http.StatusUnauthorized, "Authentication required")
			c.Abort()
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(config.HashedPassword), []byte(password)); err != nil {
			c.Header("WWW-Authenticate", `Basic realm="JetKVM Redfish"`)
			redfishError(c, http.StatusUnauthorized, "Invalid credentials")
			c.Abort()
			return
		}

		c.Next()
	}
}

func handleRedfishServiceRoot(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":    "#ServiceRoot.v1_5_0.ServiceRoot",
		"@odata.id":      "/redfish/v1/",
		"@odata.context": "/redfish/v1/$metadata#ServiceRoot.ServiceRoot",
		"Id":             "RootService",
		"Name":           "JetKVM Redfish Service",
		"RedfishVersion": redfishVersion,
		"UUID":           redfishUUID(),
		"Product":        "JetKVM",
		"Vendor":         "JetKVM",
		"Systems":        gin.H{"@odata.id": "/redfish/v1/Systems"},
		"Managers":       gin.H{"@odata.id": "/redfish/v1/Managers"},
		"Chassis":        gin.H{"@odata.id": "/redfish/v1/Chassis"},
		"SessionService": gin.H{"@odata.id": "/redfish/v1/SessionService"},
		"Links": gin.H{
			"Sessions": gin.H{"@odata.id": "/redfish/v1/SessionService/Sessions"},
		},
	})
}

func handleRedfishSystemsCollection(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"@odata.type":         "#ComputerSystemCollection.ComputerSystemCollection",
		"@odata.id":           "/redfish/v1/Systems",
		"Name":                "Computer System Collection",
		"Members@odata.count": 1,
		"Members": []gin.H{
			{"@odata.id": "/redfish/v1/Systems/" + redfishSystemID},
		},
	})
}

func handleRedfishSystem(c *gin.Context) {
	if c.Param("id") != redfishSystemID {
		redfishError(c, http.StatusNotFound, "System not found")
		return
	}

	c.JSON(http.StatusOK, redfishSystemResource())
}

// redfishSystemResource renders the ComputerSystem. Identity fields are whatever
// the managed host last reported over the host interface; anything it has not
// reported is omitted rather than guessed, so a client can tell "the host has
// not checked in" from "the host says it is a NUC".
func redfishSystemResource() gin.H {
	redfishHostMu.RLock()
	host := redfishHost
	redfishHostMu.RUnlock()

	system := gin.H{
		"@odata.type": "#ComputerSystem.v1_5_0.ComputerSystem",
		"@odata.id":   "/redfish/v1/Systems/" + redfishSystemID,
		"Id":          redfishSystemID,
		"Name":        "JetKVM Managed System",
		"SystemType":  "Physical",
		"Status": gin.H{
			"State":  "Enabled",
			"Health": "OK",
		},
		"Boot": gin.H{
			"BootSourceOverrideTarget":                         host.BootOverrideTarget,
			"BootSourceOverrideEnabled":                        host.BootOverrideEnabled,
			"BootSourceOverrideTarget@Redfish.AllowableValues": redfishBootOverrideTargets,
		},
	}

	// Manufacturer defaults to the BMC vendor only while the host is silent;
	// once it reports, its own SMBIOS values win.
	if host.Manufacturer != "" {
		system["Manufacturer"] = host.Manufacturer
	} else {
		system["Manufacturer"] = "JetKVM"
	}
	for key, value := range map[string]string{
		"BiosVersion":  host.BiosVersion,
		"Model":        host.Model,
		"SerialNumber": host.SerialNumber,
		"UUID":         host.UUID,
	} {
		if value != "" {
			system[key] = value
		}
	}

	if host.BootProgress != "" {
		progress := gin.H{"LastState": host.BootProgress}
		if !host.ReportedAt.IsZero() {
			progress["LastStateTime"] = host.ReportedAt.UTC().Format(time.RFC3339)
		}
		system["BootProgress"] = progress
	}

	if state := redfishPowerState(); state != "" {
		system["PowerState"] = state
	}

	allowable := redfishAllowableResetTypes()
	if len(allowable) > 0 {
		system["Actions"] = gin.H{
			"#ComputerSystem.Reset": gin.H{
				"target": "/redfish/v1/Systems/" + redfishSystemID +
					"/Actions/ComputerSystem.Reset",
				"ResetType@Redfish.AllowableValues": allowable,
			},
		}
	}

	return system
}

// redfishHostState holds what the managed host has reported about itself over
// the host interface, plus the boot override an operator has staged for it.
//
// The BMC has no in-band view of the host -- over the USB link it sees a NIC and
// nothing else -- so every identity field here arrives by PATCH from the host's
// firmware (NucRedfishSyncDxe) and is served straight back out of memory. It is
// deliberately not persisted: it describes the currently running host, and a
// stale copy surviving a BMC restart would be worse than reporting nothing.
type redfishHostState struct {
	BiosVersion  string
	Manufacturer string
	Model        string
	SerialNumber string
	UUID         string

	BootProgress string
	ReportedAt   time.Time

	// Boot override staged by an operator (PATCH from the LAN side) and
	// consumed by the host's firmware on its next boot.
	BootOverrideTarget  string
	BootOverrideEnabled string
}

// The lock is kept out of redfishHostState so callers can take a snapshot by
// plain assignment under the read lock and release it before rendering.
var (
	redfishHostMu sync.RWMutex
	redfishHost   = redfishHostState{
		BootOverrideTarget:  "None",
		BootOverrideEnabled: "Disabled",
	}
)

// redfishSystemPatch is the subset of ComputerSystem this service accepts. Every
// field is optional: the host reports identity and boot progress, an operator
// stages a boot override, and neither has to send the other's fields.
type redfishSystemPatch struct {
	BiosVersion  *string `json:"BiosVersion"`
	Manufacturer *string `json:"Manufacturer"`
	Model        *string `json:"Model"`
	SerialNumber *string `json:"SerialNumber"`
	UUID         *string `json:"UUID"`

	BootProgress *struct {
		LastState *string `json:"LastState"`
	} `json:"BootProgress"`

	Boot *struct {
		BootSourceOverrideTarget  *string `json:"BootSourceOverrideTarget"`
		BootSourceOverrideEnabled *string `json:"BootSourceOverrideEnabled"`
	} `json:"Boot"`
}

// redfishBootOverrideTargets are the BootSourceOverrideTarget values the host
// firmware knows how to apply (NucRedfishSyncDxe.ApplyBootOverride). Rejecting
// anything else here means an operator finds out immediately, rather than the
// setting silently doing nothing at the next boot.
//
// "Pxe" resolves to the iPXE image built into the payload firmware volume --
// that is what network boot means on this platform. "UefiHttp" is deliberately
// absent: the payload is built with NETWORK_HTTP_BOOT_ENABLE=FALSE, so no HTTP
// boot option exists for the host to select, and advertising it would be the
// same silent no-op this list exists to prevent.
var redfishBootOverrideTargets = []string{"None", "Pxe", "Hdd", "BiosSetup"}

func redfishValidBootTarget(target string) bool {
	for _, t := range redfishBootOverrideTargets {
		if t == target {
			return true
		}
	}
	return false
}

// handleRedfishSystemPatch accepts a ComputerSystem update. Two very different
// callers land here: the managed host's firmware reporting inventory and boot
// progress over the USB host interface, and an operator on the LAN staging a
// one-time boot override. Both are modelled as PATCH on the same resource
// because that is what Redfish specifies; they are told apart for logging by
// which subtree they touch.
func handleRedfishSystemPatch(c *gin.Context) {
	if c.Param("id") != redfishSystemID {
		redfishError(c, http.StatusNotFound, "System not found")
		return
	}

	var patch redfishSystemPatch
	if err := c.ShouldBindJSON(&patch); err != nil {
		redfishError(c, http.StatusBadRequest, "Malformed ComputerSystem payload")
		return
	}

	if patch.Boot != nil && patch.Boot.BootSourceOverrideTarget != nil &&
		!redfishValidBootTarget(*patch.Boot.BootSourceOverrideTarget) {
		redfishError(c, http.StatusBadRequest, fmt.Sprintf(
			"BootSourceOverrideTarget must be one of %v", redfishBootOverrideTargets))
		return
	}

	fromHost := isRedfishHostInterfaceRequest(c)

	redfishHostMu.Lock()
	if patch.BiosVersion != nil {
		redfishHost.BiosVersion = *patch.BiosVersion
	}
	if patch.Manufacturer != nil {
		redfishHost.Manufacturer = *patch.Manufacturer
	}
	if patch.Model != nil {
		redfishHost.Model = *patch.Model
	}
	if patch.SerialNumber != nil {
		redfishHost.SerialNumber = *patch.SerialNumber
	}
	if patch.UUID != nil {
		redfishHost.UUID = *patch.UUID
	}
	if patch.BootProgress != nil && patch.BootProgress.LastState != nil {
		redfishHost.BootProgress = *patch.BootProgress.LastState
	}
	if patch.Boot != nil {
		if patch.Boot.BootSourceOverrideTarget != nil {
			redfishHost.BootOverrideTarget = *patch.Boot.BootSourceOverrideTarget
		}
		if patch.Boot.BootSourceOverrideEnabled != nil {
			redfishHost.BootOverrideEnabled = *patch.Boot.BootSourceOverrideEnabled
		}
	}
	if fromHost {
		redfishHost.ReportedAt = time.Now()
	}
	snapshot := redfishHost
	redfishHostMu.Unlock()

	// This line is the acknowledgement of record: it is what proves the host's
	// firmware reached the BMC and what it said. Logged at Info so it survives
	// the default log level.
	redfishLogger.Info().
		Bool("host_interface", fromHost).
		Str("client_ip", c.ClientIP()).
		Str("bios_version", snapshot.BiosVersion).
		Str("manufacturer", snapshot.Manufacturer).
		Str("model", snapshot.Model).
		Str("serial_number", snapshot.SerialNumber).
		Str("uuid", snapshot.UUID).
		Str("boot_progress", snapshot.BootProgress).
		Str("boot_override_target", snapshot.BootOverrideTarget).
		Str("boot_override_enabled", snapshot.BootOverrideEnabled).
		Msg("Redfish ComputerSystem updated")

	// Reply with the resource as it now stands rather than 204: the host's
	// firmware reads the boot override out of this same body, so answering the
	// PATCH with it saves a round trip on the boot path.
	c.JSON(http.StatusOK, redfishSystemResource())
}

type redfishResetRequest struct {
	ResetType string `json:"ResetType"`
}

func handleRedfishSystemReset(c *gin.Context) {
	if c.Param("id") != redfishSystemID {
		redfishError(c, http.StatusNotFound, "System not found")
		return
	}

	var req redfishResetRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.ResetType == "" {
		redfishError(c, http.StatusBadRequest, "ResetType is required")
		return
	}

	status, err := performRedfishReset(req.ResetType)
	if err != nil {
		redfishError(c, status, err.Error())
		return
	}

	c.Status(status)
}

// redfishPowerState returns the Redfish PowerState ("On"/"Off") for the active
// power extension, or "" when no power extension is loaded.
func redfishPowerState() string {
	switch config.ActiveExtension {
	case "dc-power":
		if getDCState().IsOn {
			return "On"
		}
		return "Off"
	case "atx-power":
		state, err := rpcGetATXState()
		if err != nil {
			return ""
		}
		if state.Power {
			return "On"
		}
		return "Off"
	default:
		return ""
	}
}

// redfishAllowableResetTypes lists the ResetType values supported by the active
// extension. Empty when no power extension is loaded.
func redfishAllowableResetTypes() []string {
	switch config.ActiveExtension {
	case "dc-power":
		return []string{"On", "ForceOn", "ForceOff", "ForceRestart", "PowerCycle"}
	case "atx-power":
		return []string{
			"On", "ForceOn", "ForceOff", "GracefulShutdown",
			"ForceRestart", "GracefulRestart", "PushPowerButton",
		}
	default:
		return nil
	}
}

// performRedfishReset maps a Redfish ResetType onto the active power extension's
// JSON-RPC power actions. It returns the HTTP status to reply with (204 on
// success) and an error describing any failure.
func performRedfishReset(resetType string) (int, error) {
	switch config.ActiveExtension {
	case "dc-power":
		return performRedfishDCReset(resetType)
	case "atx-power":
		return performRedfishATXReset(resetType)
	default:
		return http.StatusServiceUnavailable, fmt.Errorf("no power-control extension is active")
	}
}

func performRedfishDCReset(resetType string) (int, error) {
	switch resetType {
	case "On", "ForceOn":
		return redfishActionResult(rpcSetDCPowerState(true))
	case "ForceOff":
		return redfishActionResult(rpcSetDCPowerState(false))
	case "ForceRestart", "PowerCycle":
		if err := rpcSetDCPowerState(false); err != nil {
			return http.StatusInternalServerError, err
		}
		time.Sleep(2 * time.Second)
		return redfishActionResult(rpcSetDCPowerState(true))
	default:
		return http.StatusBadRequest, fmt.Errorf("unsupported ResetType %q for dc-power extension", resetType)
	}
}

func performRedfishATXReset(resetType string) (int, error) {
	powerOn := false
	if state, err := rpcGetATXState(); err == nil {
		powerOn = state.Power
	}

	switch resetType {
	case "On", "ForceOn":
		if powerOn {
			return http.StatusNoContent, nil // already on
		}
		return redfishActionResult(rpcSetATXPowerAction("power-short"))
	case "PushPowerButton":
		return redfishActionResult(rpcSetATXPowerAction("power-short"))
	case "GracefulShutdown":
		if !powerOn {
			return http.StatusNoContent, nil // already off
		}
		return redfishActionResult(rpcSetATXPowerAction("power-short"))
	case "ForceOff":
		if !powerOn {
			return http.StatusNoContent, nil // already off
		}
		return redfishActionResult(rpcSetATXPowerAction("power-long"))
	case "ForceRestart", "GracefulRestart":
		return redfishActionResult(rpcSetATXPowerAction("reset"))
	default:
		return http.StatusBadRequest, fmt.Errorf("unsupported ResetType %q for atx-power extension", resetType)
	}
}

func redfishActionResult(err error) (int, error) {
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusNoContent, nil
}

// redfishError writes a minimal Redfish-style extended error payload.
func redfishError(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"code":    "Base.1.0.GeneralError",
			"message": message,
		},
	})
}
