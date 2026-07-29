package kvm

import (
	"fmt"
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
	redfishVersion  = "1.6.0"
	redfishSystemID = "1"
)

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
		"Id":             "RootService",
		"Name":           "JetKVM Redfish Service",
		"RedfishVersion": redfishVersion,
		"UUID":           GetDeviceID(),
		"Product":        "JetKVM",
		"Vendor":         "JetKVM",
		"Systems":        gin.H{"@odata.id": "/redfish/v1/Systems"},
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
