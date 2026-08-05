package kvm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// redfishTaskTestService gives each test its own task store, so retention and
// id allocation are deterministic and tests do not see each other's tasks.
func redfishTaskTestService(t *testing.T) {
	t.Helper()
	orig := redfishTasks
	t.Cleanup(func() { redfishTasks = orig })
	redfishTasks = &redfishTaskService{tasks: map[string]*redfishTask{}, nextID: 1}
}

// waitForTaskState polls until the task reaches a terminal state, so tests do
// not depend on goroutine scheduling.
func waitForTerminal(t *testing.T, id string) *redfishTask {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if task := redfishTasks.get(id); task != nil && task.terminal() {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach a terminal state", id)
	return nil
}

func TestRedfishTaskCompletes(t *testing.T) {
	redfishTaskTestService(t)

	task := redfishTasks.start("test", time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			progress(50, "halfway")
			return http.StatusNoContent, nil
		})

	if task.ID != "1" {
		t.Errorf("first task id = %q, want 1", task.ID)
	}

	done := waitForTerminal(t, task.ID)
	if done.State != redfishTaskCompleted {
		t.Errorf("TaskState = %q, want %q", done.State, redfishTaskCompleted)
	}
	if done.Status != "OK" {
		t.Errorf("TaskStatus = %q, want OK", done.Status)
	}
	if done.PercentComplete != 100 {
		t.Errorf("PercentComplete = %d, want 100", done.PercentComplete)
	}
	if done.EndTime.IsZero() {
		t.Error("EndTime was never set")
	}
	if len(done.Messages) < 2 {
		t.Errorf("expected the progress and completion messages, got %d", len(done.Messages))
	}
}

func TestRedfishTaskFailureBecomesException(t *testing.T) {
	redfishTaskTestService(t)

	task := redfishTasks.start("test", time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			return http.StatusInternalServerError, errors.New("the rail did not come back")
		})

	done := waitForTerminal(t, task.ID)
	if done.State != redfishTaskException {
		t.Errorf("TaskState = %q, want %q", done.State, redfishTaskException)
	}
	if done.Status != "Critical" {
		t.Errorf("TaskStatus = %q, want Critical", done.Status)
	}

	last := done.Messages[len(done.Messages)-1]
	if got := last["Message"]; got != "the rail did not come back" {
		t.Errorf("failure message = %v", got)
	}
}

// DELETE on a running task must actually stop it, not just unlink it.
func TestRedfishTaskCancelStopsTheWork(t *testing.T) {
	redfishTaskTestService(t)

	started := make(chan struct{})
	task := redfishTasks.start("test", 10*time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			close(started)
			<-ctx.Done()
			return http.StatusConflict, ctx.Err()
		})

	<-started
	if !redfishTasks.cancelTask(task.ID) {
		t.Fatal("cancelTask reported the task was missing")
	}

	done := waitForTerminal(t, task.ID)
	if done.State != redfishTaskCancelled {
		t.Errorf("TaskState = %q, want %q", done.State, redfishTaskCancelled)
	}
}

// A task that outlives its deadline is an Exception, not a Cancellation: the
// distinction is what tells an operator "it never finished" from "you stopped
// it".
func TestRedfishTaskTimeoutIsAnException(t *testing.T) {
	redfishTaskTestService(t)

	task := redfishTasks.start("test", 20*time.Millisecond,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			<-ctx.Done()
			return http.StatusGatewayTimeout, errors.New("timed out")
		})

	done := waitForTerminal(t, task.ID)
	if done.State != redfishTaskException {
		t.Errorf("TaskState = %q, want %q", done.State, redfishTaskException)
	}
}

// Retention must never evict a task that is still running -- a client holding
// its monitor URI still needs somewhere to look.
func TestRedfishTaskRetentionKeepsRunningTasks(t *testing.T) {
	redfishTaskTestService(t)

	release := make(chan struct{})
	running := redfishTasks.start("long", 10*time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			<-release
			return http.StatusNoContent, nil
		})
	t.Cleanup(func() { close(release) })

	for i := 0; i < redfishTaskRetain+8; i++ {
		task := redfishTasks.start("short", time.Second,
			func(ctx context.Context, progress func(int, string)) (int, error) {
				return http.StatusNoContent, nil
			})
		waitForTerminal(t, task.ID)
	}

	if got := len(redfishTasks.ids()); got > redfishTaskRetain+1 {
		t.Errorf("kept %d tasks, want at most %d", got, redfishTaskRetain+1)
	}
	if redfishTasks.get(running.ID) == nil {
		t.Error("the running task was evicted")
	}
}

func redfishTaskRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	withTestConfig(t).LocalAuthMode = "noPassword"

	r := gin.New()
	v1 := r.Group("/redfish/v1")
	registerRedfishClientRoutes(v1)
	return r
}

// The monitor is the contract a Redfish client actually uses: poll the Location
// header until it stops answering 202.
func TestRedfishTaskMonitorLifecycle(t *testing.T) {
	redfishTaskTestService(t)
	r := redfishTaskRouter(t)

	release := make(chan struct{})
	task := redfishTasks.start("test", 10*time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			<-release
			return http.StatusNoContent, nil
		})

	// While running: 202, with the task as the body.
	req := httptest.NewRequest(http.MethodGet, redfishTaskMonitorURI(task.ID), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("monitor while running = %d, want 202", w.Code)
	}
	if w.Header().Get("Location") == "" {
		t.Error("202 carried no Location")
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("202 body: %v", err)
	}
	if body["TaskState"] != redfishTaskRunning && body["TaskState"] != redfishTaskNew {
		t.Errorf("TaskState = %v, want New or Running", body["TaskState"])
	}

	close(release)
	waitForTerminal(t, task.ID)

	// Once complete the monitor replays the operation's own result.
	req = httptest.NewRequest(http.MethodGet, redfishTaskMonitorURI(task.ID), nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("monitor after completion = %d, want 204", w.Code)
	}
}

func TestRedfishTaskCollectionAndDelete(t *testing.T) {
	redfishTaskTestService(t)
	r := redfishTaskRouter(t)

	task := redfishTasks.start("test", time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			return http.StatusNoContent, nil
		})
	waitForTerminal(t, task.ID)

	req := httptest.NewRequest(http.MethodGet, redfishTasksURI, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var collection map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &collection); err != nil {
		t.Fatalf("collection body: %v", err)
	}
	if got := collection["Members@odata.count"]; got != float64(1) {
		t.Fatalf("Members@odata.count = %v, want 1", got)
	}

	// The member must be reachable at the URI the collection advertises --
	// edk2's RedfishTaskServiceDxe GETs each @odata.id in turn.
	req = httptest.NewRequest(http.MethodGet, redfishTaskURI(task.ID), nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET the task = %d, want 200", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, redfishTaskURI(task.ID), nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", w.Code)
	}
	if redfishTasks.get(task.ID) != nil {
		t.Error("the task survived its DELETE")
	}
}

// Tasks the BMC creates for itself must not carry a Payload: Payload.TargetUri
// is what makes edk2's RedfishTaskServiceDxe try to execute a task on the host.
func TestRedfishTaskCarriesNoPayload(t *testing.T) {
	redfishTaskTestService(t)

	task := redfishTasks.start("test", time.Second,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			return http.StatusNoContent, nil
		})

	resource := redfishTaskResource(task)
	if _, present := resource["Payload"]; present {
		t.Error("a BMC task exposed a Payload, which the host would try to execute")
	}
	if resource["HidePayload"] != true {
		t.Error("HidePayload is not set")
	}
}

// An unsupported ResetType must be refused outright rather than accepted and
// then failed asynchronously -- the caller can act on 400, but has to poll to
// discover an Exception.
func TestRedfishResetRejectsUnsupportedTypeWithoutATask(t *testing.T) {
	redfishTaskTestService(t)
	gin.SetMode(gin.TestMode)

	cfg := withTestConfig(t)
	cfg.LocalAuthMode = "noPassword"
	cfg.ActiveExtension = "dc-power"

	r := gin.New()
	v1 := r.Group("/redfish/v1")
	v1.POST("/Systems/:id/Actions/ComputerSystem.Reset", handleRedfishSystemReset)

	req := httptest.NewRequest(http.MethodPost,
		"/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
		strings.NewReader(`{"ResetType":"Nmi"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported ResetType = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if got := len(redfishTasks.ids()); got != 0 {
		t.Errorf("a rejected reset still created %d task(s)", got)
	}
}

func TestRedfishResetTargetState(t *testing.T) {
	tests := map[string]string{
		"On":               "On",
		"ForceOn":          "On",
		"PowerCycle":       "On",
		"ForceRestart":     "On",
		"GracefulRestart":  "On",
		"ForceOff":         "Off",
		"GracefulShutdown": "Off",
		"PushPowerButton":  "",
	}
	for resetType, want := range tests {
		if got := redfishResetTargetState(resetType); got != want {
			t.Errorf("redfishResetTargetState(%q) = %q, want %q", resetType, got, want)
		}
	}
}
