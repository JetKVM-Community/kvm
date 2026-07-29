package kvm

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
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

	v1 := r.Group("/redfish/v1")
	v1.Use(redfishAuthMiddleware())
	v1.Use(func(c *gin.Context) {
		c.Header("OData-Version", "4.0")
		c.Next()
	})
	{
		v1.GET("/", handleRedfishServiceRoot)
		v1.GET("/Systems", handleRedfishSystemsCollection)
		v1.GET("/Systems/:id", handleRedfishSystem)
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

	system := gin.H{
		"@odata.type":  "#ComputerSystem.v1_5_0.ComputerSystem",
		"@odata.id":    "/redfish/v1/Systems/" + redfishSystemID,
		"Id":           redfishSystemID,
		"Name":         "JetKVM Managed System",
		"SystemType":   "Physical",
		"Manufacturer": "JetKVM",
		"Status": gin.H{
			"State":  "Enabled",
			"Health": "OK",
		},
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

	c.JSON(http.StatusOK, system)
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
