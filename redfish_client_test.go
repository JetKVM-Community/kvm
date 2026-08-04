package kvm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRedfishETagMatches(t *testing.T) {
	const etag = `W/"abc123"`

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"exact", `W/"abc123"`, true},
		{"strong form of a weak tag", `"abc123"`, true},
		{"wildcard", "*", true},
		{"whitespace", ` W/"abc123" `, true},
		{"one of a list", `W/"nope", W/"abc123"`, true},
		{"mismatch", `W/"def456"`, false},
		{"empty", "", false},
		{"substring is not a match", `W/"abc"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redfishETagMatches(tt.header, etag); got != tt.want {
				t.Errorf("redfishETagMatches(%q, %q) = %v, want %v", tt.header, etag, got, tt.want)
			}
		})
	}
}

// The ETag has to change when the resource does and not otherwise -- that is the
// entire basis for the If-Match check RedfishETagDxe performs.
func TestRedfishETagTracksContent(t *testing.T) {
	a := gin.H{"Id": "1", "PowerState": "On"}
	b := gin.H{"Id": "1", "PowerState": "On"}
	c := gin.H{"Id": "1", "PowerState": "Off"}

	if redfishETag(a) != redfishETag(b) {
		t.Error("identical resources produced different ETags")
	}
	if redfishETag(a) == redfishETag(c) {
		t.Error("differing resources produced the same ETag")
	}
	if redfishETag(a) == "" {
		t.Error("ETag is empty")
	}
}

// Ids become path segments, so a client-supplied one must not be able to escape
// its collection.
func TestRedfishSanitiseID(t *testing.T) {
	tests := map[string]string{
		"Boot0001":              "Boot0001",
		"DIMM_A1":               "DIMM_A1",
		"../../secret":          "",
		"a/b":                   "",
		"a\\b":                  "",
		"a?b":                   "",
		"a#b":                   "",
		"a%2fb":                 "",
		".":                     "",
		"..":                    "",
		strings.Repeat("x", 65): "",
		strings.Repeat("x", 64): strings.Repeat("x", 64),
	}

	for in, want := range tests {
		if got := redfishSanitiseID(in); got != want {
			t.Errorf("redfishSanitiseID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedfishResourceID(t *testing.T) {
	tests := []struct {
		name     string
		body     map[string]any
		fallback string
		want     string
	}{
		{"prefers Id", map[string]any{"Id": "Boot0001", "BootOptionReference": "Boot0002"}, "BootOptionReference", "Boot0001"},
		{"falls back", map[string]any{"BootOptionReference": "Boot0002"}, "BootOptionReference", "Boot0002"},
		{"neither", map[string]any{"DisplayName": "x"}, "BootOptionReference", ""},
		{"rejects traversal", map[string]any{"Id": "../x"}, "BootOptionReference", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redfishResourceID(tt.body, tt.fallback); got != tt.want {
				t.Errorf("redfishResourceID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A POSTed resource must not be able to overwrite the identity fields the BMC
// controls, or a member could claim to live at another URI.
func TestRedfishBootOptionResourceIgnoresODataOverrides(t *testing.T) {
	resource := redfishBootOptionResource("Boot0001", map[string]any{
		"@odata.id":           "/redfish/v1/Systems/1/BootOptions/evil",
		"@odata.type":         "#Nonsense.Nonsense",
		"Id":                  "evil",
		"DisplayName":         "UEFI PM951 NVMe",
		"BootOptionReference": "Boot0001",
	})

	if got := resource["@odata.id"]; got != redfishBootOptionsURI+"/Boot0001" {
		t.Errorf("@odata.id = %v, want the canonical URI", got)
	}
	if got := resource["@odata.type"]; got != "#BootOption.v1_0_4.BootOption" {
		t.Errorf("@odata.type = %v, want the canonical type", got)
	}
	if got := resource["Id"]; got != "Boot0001" {
		t.Errorf("Id = %v, want Boot0001", got)
	}
	if got := resource["DisplayName"]; got != "UEFI PM951 NVMe" {
		t.Errorf("DisplayName = %v, want it preserved", got)
	}
}

// redfishTestRouter builds the Redfish tree with auth disabled, so route tests
// exercise routing and payloads rather than the auth middleware (covered
// separately).
func redfishTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	orig := config
	t.Cleanup(func() { config = orig })
	config.LocalAuthMode = "noPassword"

	r := gin.New()
	v1 := r.Group("/redfish/v1")
	v1.GET("/Systems/:id", handleRedfishSystem)
	registerRedfishClientRoutes(v1)
	return r
}

func redfishGetJSON(t *testing.T, r *gin.Engine, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	// Present as the managed host so host-only writes are permitted.
	req.RemoteAddr = "169.254.10.2:1024"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var body map[string]any
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("GET %s returned unparseable JSON: %v (%s)", path, err, w.Body.String())
		}
	}
	return w.Code, body
}

// The failure that started this: RedfishTaskServiceDxe reported "Device Error"
// because /redfish/v1/TaskService fell through to the web UI's index.html.
func TestRedfishTaskServiceIsJSON(t *testing.T) {
	r := redfishTestRouter(t)

	code, body := redfishGetJSON(t, r, "/redfish/v1/TaskService")
	if code != http.StatusOK {
		t.Fatalf("GET TaskService = %d, want 200", code)
	}
	if got := body["@odata.type"]; got != "#TaskService.v1_1_1.TaskService" {
		t.Errorf("@odata.type = %v", got)
	}
	if body["Tasks"] == nil {
		t.Error("TaskService has no Tasks link")
	}

	code, body = redfishGetJSON(t, r, "/redfish/v1/TaskService/Tasks")
	if code != http.StatusOK {
		t.Fatalf("GET Tasks = %d, want 200", code)
	}
	if got := body["Members@odata.count"]; got != float64(0) {
		t.Errorf("Members@odata.count = %v, want 0", got)
	}
}

// Each feature driver descends from a link on the ComputerSystem; a missing one
// is where its walk silently ends.
func TestRedfishSystemLinksToClientResources(t *testing.T) {
	r := redfishTestRouter(t)

	code, body := redfishGetJSON(t, r, "/redfish/v1/Systems/1")
	if code != http.StatusOK {
		t.Fatalf("GET System = %d, want 200", code)
	}

	for _, key := range []string{"Bios", "SecureBoot", "Memory"} {
		link, ok := body[key].(map[string]any)
		if !ok {
			t.Errorf("ComputerSystem has no %s link", key)
			continue
		}
		if link["@odata.id"] == "" || link["@odata.id"] == nil {
			t.Errorf("%s link has no @odata.id", key)
		}
	}

	boot, ok := body["Boot"].(map[string]any)
	if !ok {
		t.Fatal("ComputerSystem has no Boot object")
	}
	if boot["BootOptions"] == nil {
		t.Error("Boot has no BootOptions link")
	}
}

// Every resource the client reads must carry an ETag, or the If-Match it sends
// back on write is meaningless.
func TestRedfishResourcesCarryETags(t *testing.T) {
	r := redfishTestRouter(t)

	for _, path := range []string{
		"/redfish/v1/Systems/1",
		"/redfish/v1/Systems/1/Bios",
		"/redfish/v1/Systems/1/SecureBoot",
		"/redfish/v1/TaskService",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "169.254.10.2:1024"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, w.Code)
			continue
		}
		if w.Header().Get("ETag") == "" {
			t.Errorf("GET %s returned no ETag header", path)
		}

		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("GET %s: %v", path, err)
			continue
		}
		if body["@odata.etag"] == nil {
			t.Errorf("GET %s has no @odata.etag property", path)
		}
	}
}

// The host reports its inventory; a LAN client must not be able to invent it.
func TestRedfishHostOwnedResourcesRejectLANWrites(t *testing.T) {
	r := redfishTestRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/redfish/v1/Systems/1/BootOptions",
		strings.NewReader(`{"Id":"Boot0001","DisplayName":"invented"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.5:1024" // LAN, not the host interface
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("POST BootOptions from the LAN = %d, want 403", w.Code)
	}

	redfishClient.mu.RLock()
	_, exists := redfishClient.BootOptions["Boot0001"]
	redfishClient.mu.RUnlock()
	if exists {
		t.Error("a rejected POST still created the boot option")
	}
}

// ...but the host itself may, and what it POSTs comes back out of the collection.
func TestRedfishHostCanReportBootOptions(t *testing.T) {
	r := redfishTestRouter(t)

	t.Cleanup(func() {
		redfishClient.mu.Lock()
		redfishClient.BootOptions = map[string]map[string]any{}
		redfishClient.mu.Unlock()
	})

	req := httptest.NewRequest(http.MethodPost, "/redfish/v1/Systems/1/BootOptions",
		strings.NewReader(`{"Id":"Boot0002","DisplayName":"UEFI PXEv4 (MAC:B8AEED7E3F6E)","BootOptionEnabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "169.254.10.2:1024"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("POST BootOptions from the host = %d, want 201 (%s)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != redfishBootOptionsURI+"/Boot0002" {
		t.Errorf("Location = %q", loc)
	}

	code, body := redfishGetJSON(t, r, "/redfish/v1/Systems/1/BootOptions")
	if code != http.StatusOK {
		t.Fatalf("GET BootOptions = %d, want 200", code)
	}
	if got := body["Members@odata.count"]; got != float64(1) {
		t.Fatalf("Members@odata.count = %v, want 1", got)
	}

	code, body = redfishGetJSON(t, r, "/redfish/v1/Systems/1/BootOptions/Boot0002")
	if code != http.StatusOK {
		t.Fatalf("GET the member = %d, want 200", code)
	}
	if got := body["DisplayName"]; got != "UEFI PXEv4 (MAC:B8AEED7E3F6E)" {
		t.Errorf("DisplayName = %v", got)
	}
}

// A stale If-Match must be refused rather than silently applied -- that is the
// whole point of the header.
func TestRedfishStaleIfMatchIsRejected(t *testing.T) {
	r := redfishTestRouter(t)

	req := httptest.NewRequest(http.MethodPatch, "/redfish/v1/Systems/1/SecureBoot",
		strings.NewReader(`{"SecureBootEnable":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `W/"stale"`)
	req.RemoteAddr = "169.254.10.2:1024"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("PATCH with a stale If-Match = %d, want 412", w.Code)
	}
}

// POST to a Redfish collection means "create this and tell me where you put
// it": the service owns the Id. Memory has no natural key the client can
// supply, and demanding one made every MemoryDxe create fail with 400 -- which
// the firmware reported four hops away as "cannot find new location".
func TestRedfishMemoryPostWithoutAnIdIsAccepted(t *testing.T) {
	r := redfishTestRouter(t)

	t.Cleanup(func() {
		redfishClient.mu.Lock()
		redfishClient.Memory = map[string]map[string]any{}
		redfishClient.mu.Unlock()
	})

	body := `{"CapacityMiB":8192,"MemoryLocation":{"Socket":0,"Slot":1},"MemoryType":"DRAM"}`
	req := httptest.NewRequest(http.MethodPost, "/redfish/v1/Systems/1/Memory", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "169.254.10.2:1024"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("POST Memory without an Id = %d, want 201 (%s)", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("201 carried no Location; the client reads the new URI from it")
	}

	// The Location must actually resolve -- that is the whole point of it.
	req = httptest.NewRequest(http.MethodGet, location, nil)
	req.RemoteAddr = "169.254.10.2:1024"
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET the Location %q = %d, want 200", location, w.Code)
	}

	var member map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &member); err != nil {
		t.Fatalf("member body: %v", err)
	}
	if got := member["CapacityMiB"]; got != float64(8192) {
		t.Errorf("CapacityMiB = %v, want 8192", got)
	}
}

// Two POSTs with no Id must land on different members rather than overwriting.
func TestRedfishMemoryPostsAllocateDistinctIds(t *testing.T) {
	r := redfishTestRouter(t)

	t.Cleanup(func() {
		redfishClient.mu.Lock()
		redfishClient.Memory = map[string]map[string]any{}
		redfishClient.mu.Unlock()
	})

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/redfish/v1/Systems/1/Memory",
			strings.NewReader(`{"CapacityMiB":4096}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "169.254.10.2:1024"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("POST %d = %d, want 201", i, w.Code)
		}
		location := w.Header().Get("Location")
		if seen[location] {
			t.Fatalf("POST %d reused Location %q", i, location)
		}
		seen[location] = true
	}

	code, body := redfishGetJSON(t, r, "/redfish/v1/Systems/1/Memory")
	if code != http.StatusOK {
		t.Fatalf("GET Memory = %d", code)
	}
	if got := body["Members@odata.count"]; got != float64(3) {
		t.Errorf("Members@odata.count = %v, want 3", got)
	}
}
