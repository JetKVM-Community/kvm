package kvm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Resources that exist for the *host firmware's* Redfish client, as opposed to
// the operator-facing power control in redfish.go.
//
// EDK2's edk2-redfish-client (RedfishClientPkg) is not a general Redfish
// consumer. It is a set of feature drivers -- ComputerSystemDxe, BiosDxe,
// BootOptionDxe, MemoryDxe, SecureBootDxe, RedfishTaskServiceDxe -- each of
// which walks one branch of the tree from the service root, and each of which
// logs an error and gives up if its branch is missing. That is what the host
// was doing before this file existed:
//
//	RedfishTaskServiceFeatureCallback: Fail to dispatch Redfish tasks: Device Error
//	RedfishCollectionFeatureCallback: CollectionHandler failure: Not started
//	StartUpFeatureDriver: No InformationTypeCollectionMemberConfigLanguage of Systems returned.
//
// The "Device Error" was this service returning the web UI's index.html for
// /redfish/v1/TaskService, because gin fell through to the static handler.
//
// The direction of travel here is the opposite of the rest of redfish.go. There,
// an operator writes and the host reads. Here the *host* writes: it POSTs its
// boot options and memory modules and PATCHes its BIOS attributes, and the BMC
// stores them so an operator can read them back. So these collections are
// writable over the host interface and read-only from the LAN.
//
// Like redfishHostState, none of it is persisted. It describes the host that is
// running right now; a stale copy surviving a BMC restart would claim knowledge
// the BMC does not have.

const (
	redfishBiosID           = "Bios"
	redfishBiosRegistryID   = "BiosAttributeRegistry.v1_0_0"
	redfishSecureBootID     = "SecureBoot"
	redfishSystemURI        = "/redfish/v1/Systems/" + redfishSystemID
	redfishTaskServiceURI   = "/redfish/v1/TaskService"
	redfishRegistriesURI    = "/redfish/v1/Registries"
	redfishBiosURI          = redfishSystemURI + "/" + redfishBiosID
	redfishBootOptionsURI   = redfishSystemURI + "/BootOptions"
	redfishMemoryURI        = redfishSystemURI + "/Memory"
	redfishSecureBootURI    = redfishSystemURI + "/" + redfishSecureBootID
	redfishBiosSettingsPath = "/SD"
)

// redfishClientState is everything the host's firmware has pushed up. Guarded by
// its own mutex rather than redfishHostMu: the host interface writes here on
// every boot while an operator may be reading, and the two have nothing to do
// with the power state that redfishHostMu protects.
type redfishClientState struct {
	mu sync.RWMutex

	// BiosAttributes is the current BIOS attribute set as reported by the host,
	// and BiosPending is what an operator has staged for the next boot. Redfish
	// models these as two resources (Bios and Bios/Settings) precisely so a
	// client can tell "in effect" from "will take effect".
	BiosAttributes map[string]any
	BiosPending    map[string]any

	// BootOptions keyed by Id ("Boot0001"). The host owns these entirely; it
	// re-POSTs them whenever BDS re-enumerates.
	BootOptions map[string]map[string]any

	// Memory modules keyed by Id, same ownership.
	Memory map[string]map[string]any

	SecureBoot map[string]any
}

var redfishClient = redfishClientState{
	BiosAttributes: map[string]any{},
	BiosPending:    map[string]any{},
	BootOptions:    map[string]map[string]any{},
	Memory:         map[string]map[string]any{},
	SecureBoot: map[string]any{
		"SecureBootEnable":             false,
		"SecureBootCurrentBoot":        "Disabled",
		"SecureBootMode":               "SetupMode",
		"@Redfish.WriteableProperties": []string{"SecureBootEnable"},
	},
}

// registerRedfishClientRoutes adds the host-facing tree to the /redfish/v1
// group. Called from registerRedfishRoutes so the auth, logging and
// OData-Version middleware already apply.
func registerRedfishClientRoutes(v1 *gin.RouterGroup) {
	v1.GET("/TaskService", handleRedfishTaskService)
	v1.GET("/TaskService/Tasks", handleRedfishTasks)
	v1.GET("/TaskService/Tasks/:task", handleRedfishTask)
	v1.DELETE("/TaskService/Tasks/:task", handleRedfishTaskDelete)
	v1.GET("/TaskService/Tasks/:task/Monitor", handleRedfishTaskMonitor)

	v1.GET("/Registries", handleRedfishRegistries)
	v1.GET("/Registries/:id", handleRedfishRegistry)

	v1.GET("/Systems/:id/Bios", handleRedfishBios)
	v1.PATCH("/Systems/:id/Bios", handleRedfishBiosPatch)
	v1.GET("/Systems/:id/Bios/SD", handleRedfishBiosSettings)
	v1.PATCH("/Systems/:id/Bios/SD", handleRedfishBiosSettingsPatch)
	v1.POST("/Systems/:id/Bios/Actions/Bios.ResetBios", handleRedfishBiosReset)

	v1.GET("/Systems/:id/BootOptions", handleRedfishBootOptions)
	v1.POST("/Systems/:id/BootOptions", handleRedfishBootOptionCreate)
	v1.GET("/Systems/:id/BootOptions/:option", handleRedfishBootOption)
	v1.PATCH("/Systems/:id/BootOptions/:option", handleRedfishBootOptionPatch)
	v1.DELETE("/Systems/:id/BootOptions/:option", handleRedfishBootOptionDelete)

	v1.GET("/Systems/:id/Memory", handleRedfishMemoryCollection)
	v1.POST("/Systems/:id/Memory", handleRedfishMemoryCreate)
	v1.GET("/Systems/:id/Memory/:module", handleRedfishMemoryModule)
	v1.PATCH("/Systems/:id/Memory/:module", handleRedfishMemoryModulePatch)

	v1.GET("/Systems/:id/SecureBoot", handleRedfishSecureBoot)
	v1.PATCH("/Systems/:id/SecureBoot", handleRedfishSecureBootPatch)
}

// --- ETag ------------------------------------------------------------------
//
// RedfishETagDxe records the ETag of every resource it reads and sends it back
// as If-Match on the next write, which is how the client avoids clobbering a
// resource an operator changed underneath it. A service that returns no ETag
// makes that check vacuous, so derive a strong one from the payload: it is
// stable for unchanged content and changes whenever anything does, which is the
// whole contract.

func redfishETag(body any) string {
	encoded, err := json.Marshal(body)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("W/\"%x\"", sha256.Sum256(encoded))
}

// redfishJSON writes a resource with its ETag, honouring a conditional GET.
// The @odata.etag property carries the same value as the header because
// RedfishClientPkg reads it from the payload, not the header.
//
// The body is written with c.Data rather than c.JSON so the Content-Type is
// exactly "application/json". gin's c.JSON appends "; charset=utf-8", which
// edk2's RedfishHttpDxe does not recognise:
//
//	ParseResponseMessage: body is not in application/json format
//
// It parses the payload anyway today, so this is not load-bearing -- but a
// client that took that check seriously would drop every response, and the
// parameter buys nothing (JSON is UTF-8 by definition, RFC 8259 §8.1).
func redfishJSON(c *gin.Context, body gin.H) {
	etag := redfishETag(body)
	if etag != "" {
		body["@odata.etag"] = etag
		c.Header("ETag", etag)

		if match := c.GetHeader("If-None-Match"); match != "" && redfishETagMatches(match, etag) {
			c.Status(http.StatusNotModified)
			return
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		redfishError(c, http.StatusInternalServerError, "Failed to render the resource")
		return
	}
	c.Data(http.StatusOK, "application/json", encoded)
}

// redfishETagMatches compares an If-Match/If-None-Match header against a
// current ETag. "*" matches anything; otherwise any member of the
// comma-separated list counts, weak-comparison style (the W/ prefix is ignored),
// which is what a firmware client that round-trips the value needs.
func redfishETagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "*" {
		return true
	}
	strip := func(s string) string {
		return strings.Trim(strings.TrimPrefix(strings.TrimSpace(s), "W/"), `"`)
	}
	want := strip(etag)
	for candidate := range strings.SplitSeq(header, ",") {
		if strip(candidate) == want {
			return true
		}
	}
	return false
}

// redfishCheckIfMatch enforces a conditional write. Returns false (and writes
// the response) when the caller's If-Match does not match, so handlers can
// simply return.
func redfishCheckIfMatch(c *gin.Context, current gin.H) bool {
	match := c.GetHeader("If-Match")
	if match == "" {
		return true
	}
	if redfishETagMatches(match, redfishETag(current)) {
		return true
	}
	redfishError(c, http.StatusPreconditionFailed, "ETag does not match the current resource")
	return false
}

// --- write authorisation ---------------------------------------------------

// redfishHostWritable rejects writes to the host-owned resources from anywhere
// but the host interface. An operator reads the host's inventory; only the host
// reports it. Without this, a LAN client could claim the host has memory or boot
// options it does not have, and the BMC would repeat that back as fact.
func redfishHostWritable(c *gin.Context) bool {
	if isRedfishHostInterfaceRequest(c) {
		return true
	}
	redfishError(c, http.StatusForbidden,
		"This resource is reported by the managed host and is writable only over the host interface")
	return false
}

func redfishSystemMatches(c *gin.Context) bool {
	if c.Param("id") == redfishSystemID {
		return true
	}
	redfishError(c, http.StatusNotFound, "System not found")
	return false
}

// --- TaskService -----------------------------------------------------------
//
// The tasks themselves, their lifecycle and the task monitor are in
// redfish_task.go. Only the service resource lives here, next to the rest of
// the tree the host firmware walks -- RedfishTaskServiceDxe reads it on every
// boot, and reported "Fail to dispatch Redfish tasks: Device Error" for as long
// as gin answered this URI with the web UI's index.html.

func handleRedfishTaskService(c *gin.Context) {
	redfishJSON(c, gin.H{
		"@odata.type":                     "#TaskService.v1_1_1.TaskService",
		"@odata.id":                       redfishTaskServiceURI,
		"Id":                              "TaskService",
		"Name":                            "Task Service",
		"ServiceEnabled":                  true,
		"DateTime":                        time.Now().UTC().Format(time.RFC3339),
		"CompletedTaskOverWritePolicy":    "Oldest",
		"LifeCycleEventOnTaskStateChange": false,
		"Status": gin.H{
			"State":  "Enabled",
			"Health": "OK",
		},
		"Tasks": gin.H{"@odata.id": redfishTasksURI},
	})
}

// --- Registries ------------------------------------------------------------
//
// BiosAttributeRegistryDxe looks up the registry named by Bios.AttributeRegistry
// to learn each attribute's type and constraints. The registry itself is
// generated by the host from its HII forms and PATCHed to the Bios resource, so
// what the BMC serves is the pointer, not the content.

func handleRedfishRegistries(c *gin.Context) {
	redfishJSON(c, gin.H{
		"@odata.type":         "#MessageRegistryFileCollection.MessageRegistryFileCollection",
		"@odata.id":           redfishRegistriesURI,
		"Name":                "Registry File Collection",
		"Members@odata.count": 1,
		"Members": []gin.H{
			{"@odata.id": redfishRegistriesURI + "/" + redfishBiosRegistryID},
		},
	})
}

func handleRedfishRegistry(c *gin.Context) {
	id := c.Param("id")
	if id != redfishBiosRegistryID {
		redfishError(c, http.StatusNotFound, "Registry not found")
		return
	}

	redfishJSON(c, gin.H{
		"@odata.type": "#MessageRegistryFile.v1_1_0.MessageRegistryFile",
		"@odata.id":   redfishRegistriesURI + "/" + id,
		"Id":          id,
		"Name":        "BIOS Attribute Registry",
		"Registry":    id,
		"Languages":   []string{"en"},
		"Location": []gin.H{
			{
				"Language": "en",
				"Uri":      redfishRegistriesURI + "/" + id + "/registry.json",
			},
		},
	})
}

// --- Bios ------------------------------------------------------------------
//
// Two resources, because Redfish separates them: Bios is what is in effect now,
// Bios/SD ("Settings Data") is what will be applied at the next boot. The host
// reports the former on every boot and consumes the latter; an operator writes
// the latter and never the former. The link between them is the
// @Redfish.Settings annotation, which is how BiosDxe finds the pending resource.

func handleRedfishBios(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}
	redfishJSON(c, redfishBiosResource())
}

func redfishBiosResource() gin.H {
	redfishClient.mu.RLock()
	attributes := redfishCopyMap(redfishClient.BiosAttributes)
	redfishClient.mu.RUnlock()

	redfishHostMu.RLock()
	version := redfishHost.BiosVersion
	redfishHostMu.RUnlock()

	resource := gin.H{
		"@odata.type":       "#Bios.v1_0_9.Bios",
		"@odata.id":         redfishBiosURI,
		"Id":                redfishBiosID,
		"Name":              "BIOS Configuration",
		"AttributeRegistry": redfishBiosRegistryID,
		"Attributes":        attributes,
		"@Redfish.Settings": gin.H{
			"@odata.type":    "#Settings.v1_3_3.Settings",
			"SettingsObject": gin.H{"@odata.id": redfishBiosURI + redfishBiosSettingsPath},
		},
		"Actions": gin.H{
			"#Bios.ResetBios": gin.H{
				"target": redfishBiosURI + "/Actions/Bios.ResetBios",
			},
		},
	}
	if version != "" {
		resource["BiosVersion"] = version
	}
	return resource
}

func handleRedfishBiosPatch(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}
	if !redfishCheckIfMatch(c, redfishBiosResource()) {
		return
	}

	var patch struct {
		Attributes        map[string]any `json:"Attributes"`
		AttributeRegistry *string        `json:"AttributeRegistry"`
	}
	if err := c.ShouldBindJSON(&patch); err != nil {
		redfishError(c, http.StatusBadRequest, "Malformed request body")
		return
	}

	redfishClient.mu.Lock()
	for key, value := range patch.Attributes {
		redfishClient.BiosAttributes[key] = value
	}
	count := len(redfishClient.BiosAttributes)
	redfishClient.mu.Unlock()

	redfishLogger.Info().
		Int("reported", len(patch.Attributes)).
		Int("total", count).
		Msg("host reported BIOS attributes")

	redfishJSON(c, redfishBiosResource())
}

func handleRedfishBiosSettings(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}
	redfishJSON(c, redfishBiosSettingsResource())
}

func redfishBiosSettingsResource() gin.H {
	redfishClient.mu.RLock()
	pending := redfishCopyMap(redfishClient.BiosPending)
	redfishClient.mu.RUnlock()

	return gin.H{
		"@odata.type":       "#Bios.v1_0_9.Bios",
		"@odata.id":         redfishBiosURI + redfishBiosSettingsPath,
		"Id":                "SD",
		"Name":              "BIOS Pending Settings",
		"AttributeRegistry": redfishBiosRegistryID,
		"Attributes":        pending,
	}
}

// handleRedfishBiosSettingsPatch stages attributes for the next boot. Unlike the
// rest of this file it is writable from the LAN -- staging a setting is the
// operator's job, and consuming it is the host's.
func handleRedfishBiosSettingsPatch(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}
	if !redfishCheckIfMatch(c, redfishBiosSettingsResource()) {
		return
	}

	var patch struct {
		Attributes map[string]any `json:"Attributes"`
	}
	if err := c.ShouldBindJSON(&patch); err != nil {
		redfishError(c, http.StatusBadRequest, "Malformed request body")
		return
	}

	redfishClient.mu.Lock()
	for key, value := range patch.Attributes {
		redfishClient.BiosPending[key] = value
	}
	redfishClient.mu.Unlock()

	redfishLogger.Info().
		Int("staged", len(patch.Attributes)).
		Bool("host_interface", isRedfishHostInterfaceRequest(c)).
		Msg("BIOS settings staged for the next boot")

	redfishJSON(c, redfishBiosSettingsResource())
}

// handleRedfishBiosReset discards anything staged. The host applies defaults
// itself; all the BMC can do is stop asking for the old values.
func handleRedfishBiosReset(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}

	redfishClient.mu.Lock()
	redfishClient.BiosPending = map[string]any{}
	redfishClient.mu.Unlock()

	redfishLogger.Info().Msg("pending BIOS settings cleared by Bios.ResetBios")
	c.Status(http.StatusNoContent)
}

// --- BootOptions -----------------------------------------------------------
//
// BootOptionCollectionDxe POSTs one member per Boot#### variable and BootOptionDxe
// keeps them current. This is what makes an operator able to see the host's real
// boot menu -- "NVMe: PM951", "PXEv4 (MAC:...)" -- rather than the four opaque
// BootSourceOverrideTarget enums in redfish.go.

func handleRedfishBootOptions(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}

	redfishClient.mu.RLock()
	ids := redfishSortedKeys(redfishClient.BootOptions)
	redfishClient.mu.RUnlock()

	members := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		members = append(members, gin.H{"@odata.id": redfishBootOptionsURI + "/" + id})
	}

	redfishJSON(c, gin.H{
		"@odata.type":         "#BootOptionCollection.BootOptionCollection",
		"@odata.id":           redfishBootOptionsURI,
		"Name":                "Boot Option Collection",
		"Members@odata.count": len(members),
		"Members":             members,
	})
}

func handleRedfishBootOptionCreate(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}

	body, err := redfishBindResource(c)
	if err != nil {
		return
	}

	id := redfishResourceID(body, "BootOptionReference")
	if id == "" {
		redfishError(c, http.StatusBadRequest, "Id or BootOptionReference is required")
		return
	}

	redfishClient.mu.Lock()
	redfishClient.BootOptions[id] = body
	count := len(redfishClient.BootOptions)
	redfishClient.mu.Unlock()

	redfishLogger.Info().
		Str("id", id).
		Str("display_name", redfishString(body, "DisplayName")).
		Int("total", count).
		Msg("host reported a boot option")

	c.Header("Location", redfishBootOptionsURI+"/"+id)
	c.JSON(http.StatusCreated, redfishBootOptionResource(id, body))
}

func handleRedfishBootOption(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}

	id := c.Param("option")
	redfishClient.mu.RLock()
	body, ok := redfishClient.BootOptions[id]
	body = redfishCopyMap(body)
	redfishClient.mu.RUnlock()

	if !ok {
		redfishError(c, http.StatusNotFound, "Boot option not found")
		return
	}
	redfishJSON(c, redfishBootOptionResource(id, body))
}

func handleRedfishBootOptionPatch(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}

	id := c.Param("option")
	redfishClient.mu.RLock()
	existing, ok := redfishClient.BootOptions[id]
	existing = redfishCopyMap(existing)
	redfishClient.mu.RUnlock()

	if !ok {
		redfishError(c, http.StatusNotFound, "Boot option not found")
		return
	}
	if !redfishCheckIfMatch(c, redfishBootOptionResource(id, existing)) {
		return
	}

	patch, err := redfishBindResource(c)
	if err != nil {
		return
	}

	redfishClient.mu.Lock()
	for key, value := range patch {
		redfishClient.BootOptions[id][key] = value
	}
	merged := redfishCopyMap(redfishClient.BootOptions[id])
	redfishClient.mu.Unlock()

	redfishJSON(c, redfishBootOptionResource(id, merged))
}

func handleRedfishBootOptionDelete(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}

	id := c.Param("option")
	redfishClient.mu.Lock()
	_, ok := redfishClient.BootOptions[id]
	delete(redfishClient.BootOptions, id)
	redfishClient.mu.Unlock()

	if !ok {
		redfishError(c, http.StatusNotFound, "Boot option not found")
		return
	}

	redfishLogger.Info().Str("id", id).Msg("host removed a boot option")
	c.Status(http.StatusNoContent)
}

func redfishBootOptionResource(id string, body map[string]any) gin.H {
	resource := gin.H{
		"@odata.type": "#BootOption.v1_0_4.BootOption",
		"@odata.id":   redfishBootOptionsURI + "/" + id,
		"Id":          id,
		"Name":        "Boot Option",
	}
	for key, value := range body {
		if strings.HasPrefix(key, "@odata.") {
			continue
		}
		resource[key] = value
	}
	resource["Id"] = id
	return resource
}

// --- Memory ----------------------------------------------------------------

func handleRedfishMemoryCollection(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}

	redfishClient.mu.RLock()
	ids := redfishSortedKeys(redfishClient.Memory)
	redfishClient.mu.RUnlock()

	members := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		members = append(members, gin.H{"@odata.id": redfishMemoryURI + "/" + id})
	}

	redfishJSON(c, gin.H{
		"@odata.type":         "#MemoryCollection.MemoryCollection",
		"@odata.id":           redfishMemoryURI,
		"Name":                "Memory Collection",
		"Members@odata.count": len(members),
		"Members":             members,
	})
}

func handleRedfishMemoryCreate(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}

	body, err := redfishBindResource(c)
	if err != nil {
		return
	}

	id := redfishResourceID(body, "MemoryLocation")
	if id == "" {
		redfishError(c, http.StatusBadRequest, "Id is required")
		return
	}

	redfishClient.mu.Lock()
	redfishClient.Memory[id] = body
	count := len(redfishClient.Memory)
	redfishClient.mu.Unlock()

	redfishLogger.Info().Str("id", id).Int("total", count).Msg("host reported a memory module")

	c.Header("Location", redfishMemoryURI+"/"+id)
	c.JSON(http.StatusCreated, redfishMemoryResource(id, body))
}

func handleRedfishMemoryModule(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}

	id := c.Param("module")
	redfishClient.mu.RLock()
	body, ok := redfishClient.Memory[id]
	body = redfishCopyMap(body)
	redfishClient.mu.RUnlock()

	if !ok {
		redfishError(c, http.StatusNotFound, "Memory module not found")
		return
	}
	redfishJSON(c, redfishMemoryResource(id, body))
}

func handleRedfishMemoryModulePatch(c *gin.Context) {
	if !redfishSystemMatches(c) || !redfishHostWritable(c) {
		return
	}

	id := c.Param("module")
	redfishClient.mu.RLock()
	existing, ok := redfishClient.Memory[id]
	existing = redfishCopyMap(existing)
	redfishClient.mu.RUnlock()

	if !ok {
		redfishError(c, http.StatusNotFound, "Memory module not found")
		return
	}
	if !redfishCheckIfMatch(c, redfishMemoryResource(id, existing)) {
		return
	}

	patch, err := redfishBindResource(c)
	if err != nil {
		return
	}

	redfishClient.mu.Lock()
	for key, value := range patch {
		redfishClient.Memory[id][key] = value
	}
	merged := redfishCopyMap(redfishClient.Memory[id])
	redfishClient.mu.Unlock()

	redfishJSON(c, redfishMemoryResource(id, merged))
}

func redfishMemoryResource(id string, body map[string]any) gin.H {
	resource := gin.H{
		"@odata.type": "#Memory.v1_7_1.Memory",
		"@odata.id":   redfishMemoryURI + "/" + id,
		"Id":          id,
		"Name":        "Memory Module",
	}
	for key, value := range body {
		if strings.HasPrefix(key, "@odata.") {
			continue
		}
		resource[key] = value
	}
	resource["Id"] = id
	return resource
}

// --- SecureBoot ------------------------------------------------------------

func handleRedfishSecureBoot(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}
	redfishJSON(c, redfishSecureBootResource())
}

func redfishSecureBootResource() gin.H {
	redfishClient.mu.RLock()
	state := redfishCopyMap(redfishClient.SecureBoot)
	redfishClient.mu.RUnlock()

	resource := gin.H{
		"@odata.type": "#SecureBoot.v1_1_0.SecureBoot",
		"@odata.id":   redfishSecureBootURI,
		"Id":          redfishSecureBootID,
		"Name":        "UEFI Secure Boot",
	}
	for key, value := range state {
		resource[key] = value
	}
	return resource
}

func handleRedfishSecureBootPatch(c *gin.Context) {
	if !redfishSystemMatches(c) {
		return
	}
	if !redfishCheckIfMatch(c, redfishSecureBootResource()) {
		return
	}

	patch, err := redfishBindResource(c)
	if err != nil {
		return
	}

	redfishClient.mu.Lock()
	for key, value := range patch {
		if strings.HasPrefix(key, "@odata.") {
			continue
		}
		redfishClient.SecureBoot[key] = value
	}
	redfishClient.mu.Unlock()

	redfishJSON(c, redfishSecureBootResource())
}

// --- helpers ---------------------------------------------------------------

func redfishBindResource(c *gin.Context) (map[string]any, error) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		redfishError(c, http.StatusBadRequest, "Malformed request body")
		return nil, err
	}
	return body, nil
}

// redfishResourceID picks the identifier out of a POSTed resource. Redfish says
// Id, but a client that is mirroring UEFI state often has a more meaningful
// natural key (BootOptionReference is the "Boot0001" name), so accept that as a
// fallback rather than rejecting the create.
func redfishResourceID(body map[string]any, fallbackKey string) string {
	if id := redfishString(body, "Id"); id != "" {
		return redfishSanitiseID(id)
	}
	if id := redfishString(body, fallbackKey); id != "" {
		return redfishSanitiseID(id)
	}
	return ""
}

// redfishSanitiseID keeps a client-supplied Id from escaping its collection.
// These become path segments, so anything that could traverse or split the URI
// is dropped rather than escaped -- a legitimate Id never contains them.
func redfishSanitiseID(id string) string {
	if strings.ContainsAny(id, "/\\?#%") || id == "." || id == ".." {
		return ""
	}
	if len(id) > 64 {
		return ""
	}
	return id
}

func redfishString(body map[string]any, key string) string {
	if value, ok := body[key].(string); ok {
		return value
	}
	return ""
}

func redfishCopyMap[V any](in map[string]V) map[string]V {
	out := make(map[string]V, len(in))
	maps.Copy(out, in)
	return out
}

func redfishSortedKeys[V any](in map[string]V) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
