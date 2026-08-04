package kvm

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// The Redfish TaskService, for operations the BMC cannot honestly answer inside
// one HTTP round trip.
//
// A power action is the motivating case. "PowerCycle" on the dc-power extension
// drops the rail, waits two seconds and raises it, and the thing the caller
// actually wants to know -- did the host come back -- is not knowable for
// several seconds after that. Doing it synchronously meant a handler that slept
// two seconds inside the request and then returned 204 describing nothing more
// than "the RPC did not error".
//
// Redfish's answer is a Task: the action returns 202 with a Location pointing at
// a task monitor, the work continues, and the client polls until the task
// reaches a terminal state. That is what this file implements. Each task owns a
// goroutine and a cancellable context, so DELETE on a running task means
// something.
//
// The host firmware also reads this collection. edk2's RedfishTaskServiceDxe
// walks Members on every boot looking for work addressed to it, keyed by
// Payload.TargetUri. Tasks created here carry no Payload -- they are the BMC's
// own work, not the host's -- and by the time a host boots they are in a
// terminal state, which that driver skips explicitly ("Task state: 0x7,
// ignore"). Queueing work *for* the host is a different feature and is not
// implemented: the payload build resolves RedfishTaskLib to the Null instance,
// so the host never reports a task complete, and anything queued would be
// re-executed on every subsequent boot.

const (
	redfishTasksURI = redfishTaskServiceURI + "/Tasks"

	// How long a power action is given to reach its target state before the
	// task gives up. A cold boot of the managed host takes tens of seconds;
	// this only waits for the *power state*, which follows the rail.
	redfishTaskPowerTimeout = 30 * time.Second

	// How often the task polls the power extension while waiting.
	redfishTaskPollInterval = 500 * time.Millisecond

	// Completed tasks kept before the oldest is evicted, matching the
	// CompletedTaskOverWritePolicy this service advertises.
	redfishTaskRetain = 32
)

// Redfish TaskState values. Only the terminal ones and Running are produced
// here; the full set is in the schema.
const (
	redfishTaskNew       = "New"
	redfishTaskRunning   = "Running"
	redfishTaskCompleted = "Completed"
	redfishTaskException = "Exception"
	redfishTaskCancelled = "Cancelled"
)

// redfishTask is one unit of asynchronous work. Everything a client can observe
// is guarded by the service mutex; the goroutine mutates it only through the
// service's helpers.
type redfishTask struct {
	ID              string
	Name            string
	State           string
	Status          string // "OK", "Warning" or "Critical"
	PercentComplete int
	StartTime       time.Time
	EndTime         time.Time
	Messages        []gin.H

	// Result is the status code the operation would have returned had it been
	// synchronous. The task monitor replays it once the task is terminal, which
	// is what lets a client treat the monitor as "the response, eventually".
	ResultStatus int

	cancel context.CancelFunc
}

func (t *redfishTask) terminal() bool {
	switch t.State {
	case redfishTaskCompleted, redfishTaskException, redfishTaskCancelled:
		return true
	}
	return false
}

type redfishTaskService struct {
	mu     sync.RWMutex
	tasks  map[string]*redfishTask
	nextID int
}

var redfishTasks = &redfishTaskService{
	tasks:  map[string]*redfishTask{},
	nextID: 1,
}

// start creates a task and runs work in its own goroutine. It returns the task
// as it stands at creation, which is what the 202 response carries.
//
// work receives a context that is cancelled by DELETE on the task or by the
// deadline, and a progress callback. Its error becomes the task's failure
// message; the status it returns is what the task monitor replays.
func (s *redfishTaskService) start(
	name string,
	timeout time.Duration,
	work func(ctx context.Context, progress func(percent int, message string)) (int, error),
) *redfishTask {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)

	s.mu.Lock()
	id := strconv.Itoa(s.nextID)
	s.nextID++
	task := &redfishTask{
		ID:        id,
		Name:      name,
		State:     redfishTaskNew,
		Status:    "OK",
		StartTime: time.Now(),
		cancel:    cancel,
	}
	s.tasks[id] = task
	s.evictLocked()
	s.mu.Unlock()

	redfishLogger.Info().Str("task", id).Str("name", name).Msg("Redfish task created")

	go func() {
		defer cancel()

		s.update(id, func(t *redfishTask) {
			t.State = redfishTaskRunning
		})

		status, err := work(ctx, func(percent int, message string) {
			s.update(id, func(t *redfishTask) {
				t.PercentComplete = percent
				if message != "" {
					t.Messages = append(t.Messages, redfishTaskMessage(message, "OK"))
				}
			})
		})

		s.update(id, func(t *redfishTask) {
			t.EndTime = time.Now()
			t.ResultStatus = status
			switch {
			case err != nil && ctx.Err() == context.Canceled:
				t.State = redfishTaskCancelled
				t.Status = "Warning"
				t.Messages = append(t.Messages, redfishTaskMessage("Task cancelled", "Warning"))
			case err != nil:
				t.State = redfishTaskException
				t.Status = "Critical"
				t.Messages = append(t.Messages, redfishTaskMessage(err.Error(), "Critical"))
			default:
				t.State = redfishTaskCompleted
				t.PercentComplete = 100
				t.Messages = append(t.Messages, redfishTaskMessage("Task completed successfully", "OK"))
			}
		})

		final := s.get(id)
		if final != nil {
			redfishLogger.Info().
				Str("task", id).
				Str("name", name).
				Str("state", final.State).
				Dur("took", final.EndTime.Sub(final.StartTime)).
				Msg("Redfish task finished")
		}
	}()

	return s.get(id)
}

// update applies fn to a task under the write lock and is the only way the
// running goroutine touches shared state.
func (s *redfishTaskService) update(id string, fn func(*redfishTask)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if task, ok := s.tasks[id]; ok {
		fn(task)
	}
}

// get returns a snapshot. The copy matters: callers render it after releasing
// the lock, and the goroutine may still be writing the original.
func (s *redfishTaskService) get(id string) *redfishTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	task, ok := s.tasks[id]
	if !ok {
		return nil
	}
	snapshot := *task
	snapshot.Messages = append([]gin.H(nil), task.Messages...)
	return &snapshot
}

func (s *redfishTaskService) ids() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.tasks))
	for id := range s.tasks {
		ids = append(ids, id)
	}
	// Numeric order, so the collection reads in creation order rather than
	// "1, 10, 2".
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.Atoi(ids[i])
		b, _ := strconv.Atoi(ids[j])
		return a < b
	})
	return ids
}

// cancel stops a running task. Returns false if there is no such task.
func (s *redfishTaskService) cancelTask(id string) bool {
	s.mu.Lock()
	task, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	cancel := task.cancel
	running := !task.terminal()
	s.mu.Unlock()

	if running && cancel != nil {
		cancel()
		return true
	}

	// Already finished: DELETE means "forget it".
	s.mu.Lock()
	delete(s.tasks, id)
	s.mu.Unlock()
	return true
}

// evictLocked drops the oldest terminal tasks once the retention limit is
// exceeded. Running tasks are never evicted -- a client holding their monitor
// URI still needs somewhere to look. Caller holds the write lock.
func (s *redfishTaskService) evictLocked() {
	if len(s.tasks) <= redfishTaskRetain {
		return
	}

	finished := make([]*redfishTask, 0, len(s.tasks))
	for _, task := range s.tasks {
		if task.terminal() {
			finished = append(finished, task)
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		return finished[i].EndTime.Before(finished[j].EndTime)
	})

	for _, task := range finished {
		if len(s.tasks) <= redfishTaskRetain {
			return
		}
		delete(s.tasks, task.ID)
	}
}

func redfishTaskMessage(message, severity string) gin.H {
	return gin.H{
		"@odata.type": "#Message.v1_1_2.Message",
		"MessageId":   "Base.1.0.Success",
		"Message":     message,
		"Severity":    severity,
		"Resolution":  "None",
	}
}

// --- resources -------------------------------------------------------------

func redfishTaskURI(id string) string { return redfishTasksURI + "/" + id }
func redfishTaskMonitorURI(id string) string {
	return redfishTaskURI(id) + "/Monitor"
}

func redfishTaskResource(task *redfishTask) gin.H {
	resource := gin.H{
		"@odata.type":     "#Task.v1_4_3.Task",
		"@odata.id":       redfishTaskURI(task.ID),
		"Id":              task.ID,
		"Name":            task.Name,
		"TaskState":       task.State,
		"TaskStatus":      task.Status,
		"PercentComplete": task.PercentComplete,
		"StartTime":       task.StartTime.UTC().Format(time.RFC3339),
		"TaskMonitor":     redfishTaskMonitorURI(task.ID),
		// No Payload: these are the BMC's own operations, and a Payload with a
		// TargetUri is what makes edk2's RedfishTaskServiceDxe try to execute a
		// task on the host.
		"HidePayload": true,
		"Messages":    task.Messages,
	}
	if !task.EndTime.IsZero() {
		resource["EndTime"] = task.EndTime.UTC().Format(time.RFC3339)
	}
	if task.Messages == nil {
		resource["Messages"] = []gin.H{}
	}
	return resource
}

func handleRedfishTasks(c *gin.Context) {
	ids := redfishTasks.ids()
	members := make([]gin.H, 0, len(ids))
	for _, id := range ids {
		members = append(members, gin.H{"@odata.id": redfishTaskURI(id)})
	}

	redfishJSON(c, gin.H{
		"@odata.type":         "#TaskCollection.TaskCollection",
		"@odata.id":           redfishTasksURI,
		"Name":                "Task Collection",
		"Members@odata.count": len(members),
		"Members":             members,
	})
}

func handleRedfishTask(c *gin.Context) {
	task := redfishTasks.get(c.Param("task"))
	if task == nil {
		redfishError(c, http.StatusNotFound, "Task not found")
		return
	}
	redfishJSON(c, redfishTaskResource(task))
}

// handleRedfishTaskMonitor implements the task monitor: 202 with the task while
// the work is in flight, and the operation's own eventual result once it is
// not. This is what makes "poll the Location header until it stops returning
// 202" -- the pattern every Redfish client implements -- do the right thing.
func handleRedfishTaskMonitor(c *gin.Context) {
	task := redfishTasks.get(c.Param("task"))
	if task == nil {
		redfishError(c, http.StatusNotFound, "Task not found")
		return
	}

	if !task.terminal() {
		c.Header("Location", redfishTaskMonitorURI(task.ID))
		c.Header("Retry-After", "1")
		c.JSON(http.StatusAccepted, redfishTaskResource(task))
		return
	}

	switch task.State {
	case redfishTaskCompleted:
		status := task.ResultStatus
		if status == 0 {
			status = http.StatusNoContent
		}
		if status == http.StatusNoContent {
			c.Status(status)
			return
		}
		c.JSON(status, redfishTaskResource(task))
	case redfishTaskCancelled:
		redfishError(c, http.StatusConflict, "Task was cancelled")
	default:
		message := "Task failed"
		if len(task.Messages) > 0 {
			if text, ok := task.Messages[len(task.Messages)-1]["Message"].(string); ok {
				message = text
			}
		}
		status := task.ResultStatus
		if status == 0 || status < 400 {
			status = http.StatusInternalServerError
		}
		redfishError(c, status, message)
	}
}

// handleRedfishTaskDelete cancels a running task or forgets a finished one.
func handleRedfishTaskDelete(c *gin.Context) {
	if !redfishTasks.cancelTask(c.Param("task")) {
		redfishError(c, http.StatusNotFound, "Task not found")
		return
	}
	c.Status(http.StatusNoContent)
}

// --- power actions as tasks ------------------------------------------------

// redfishResetTargetState is the PowerState a ResetType is trying to reach, or
// "" when the answer is not a steady state worth waiting for (PushPowerButton
// is a button press, not a request for a particular state).
func redfishResetTargetState(resetType string) string {
	switch resetType {
	case "On", "ForceOn", "ForceRestart", "GracefulRestart", "PowerCycle":
		return "On"
	case "ForceOff", "GracefulShutdown":
		return "Off"
	default:
		return ""
	}
}

// redfishStartResetTask performs a reset in the background and waits for the
// host to actually reach the requested power state. Returning the RPC's status
// immediately -- which is what this used to do -- says only that the message was
// sent; a PowerCycle that drops the rail and fails to bring it back looked
// identical to one that worked.
func redfishStartResetTask(resetType string) *redfishTask {
	return redfishTasks.start(
		fmt.Sprintf("ComputerSystem.Reset %s", resetType),
		redfishTaskPowerTimeout,
		func(ctx context.Context, progress func(int, string)) (int, error) {
			progress(10, fmt.Sprintf("Performing %s", resetType))

			status, err := performRedfishReset(resetType)
			if err != nil {
				return status, err
			}

			target := redfishResetTargetState(resetType)
			if target == "" {
				return status, nil
			}

			progress(50, fmt.Sprintf("Waiting for PowerState %s", target))

			ticker := time.NewTicker(redfishTaskPollInterval)
			defer ticker.Stop()

			for {
				if state := redfishPowerState(); state == target {
					return status, nil
				} else if state == "" {
					// No power extension can report state. The action was
					// accepted, so do not fail the task over an observation we
					// were never able to make.
					return status, nil
				}

				select {
				case <-ctx.Done():
					if ctx.Err() == context.Canceled {
						return http.StatusConflict, fmt.Errorf("cancelled while waiting for PowerState %s", target)
					}
					return http.StatusGatewayTimeout,
						fmt.Errorf("timed out after %s waiting for PowerState %s", redfishTaskPowerTimeout, target)
				case <-ticker.C:
				}
			}
		},
	)
}
