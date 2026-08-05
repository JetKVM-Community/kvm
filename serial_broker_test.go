package kvm

import (
	"os"
	"sync"
	"testing"
	"time"
)

// recorder is a serialSubscriber that keeps what it was given.
type recorder struct {
	mu   sync.Mutex
	data []byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, p...)
	return len(p), nil
}

func (r *recorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.data)
}

// newTestBroker builds a broker around an os.Pipe instead of /dev/ttyGS0, so
// the fan-out logic is testable off the device. The write end stands in for the
// host.
func newTestBroker(t *testing.T) (*serialBroker, *os.File) {
	t.Helper()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	b := &serialBroker{subs: map[*subscription]struct{}{}}
	b.file = pr
	b.closed = make(chan struct{})
	go b.readLoop(pr, b.closed)

	t.Cleanup(func() {
		pw.Close()
		pr.Close()
	})
	return b, pw
}

func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// The regression this exists for: cdc_acm_console.go used to open /dev/ttyGS0
// for itself rather than subscribing here. Two readers of one tty do not each
// see the stream -- read() hands every byte to exactly one of them -- so a
// browser console silently ate the host output an IPMI SOL session was waiting
// for, and vice versa. Both ends looked like a console that connects and then
// shows nothing.
func TestSerialBrokerFansOutToEverySubscriber(t *testing.T) {
	b, host := newTestBroker(t)

	browser := &recorder{}
	sol := &recorder{}

	stopBrowser, err := b.Subscribe(browser)
	if err != nil {
		t.Fatalf("subscribe browser: %v", err)
	}
	defer stopBrowser()

	stopSOL, err := b.Subscribe(sol)
	if err != nil {
		t.Fatalf("subscribe sol: %v", err)
	}
	defer stopSOL()

	if _, err := host.Write([]byte("login: ")); err != nil {
		t.Fatalf("host write: %v", err)
	}

	if !waitFor(t, func() bool {
		return browser.String() == "login: " && sol.String() == "login: "
	}) {
		t.Fatalf("both subscribers should see the same bytes; browser=%q sol=%q",
			browser.String(), sol.String())
	}
}

// A subscriber attaching to an idle host would otherwise see nothing until the
// host next writes, which on a machine sitting at a prompt can be indefinite --
// "ipmitool sol activate" then looks like it failed.
func TestSerialBrokerReplaysScrollbackOnAttach(t *testing.T) {
	b, host := newTestBroker(t)

	first := &recorder{}
	stopFirst, err := b.Subscribe(first)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer stopFirst()

	if _, err := host.Write([]byte("earlier output\n")); err != nil {
		t.Fatalf("host write: %v", err)
	}
	if !waitFor(t, func() bool { return first.String() == "earlier output\n" }) {
		t.Fatalf("first subscriber missed the write: %q", first.String())
	}

	// A console attaching afterwards should still be handed what it missed.
	late := &recorder{}
	stopLate, err := b.Subscribe(late)
	if err != nil {
		t.Fatalf("subscribe late: %v", err)
	}
	defer stopLate()

	if got := late.String(); got != "earlier output\n" {
		t.Errorf("late subscriber got %q, want the scrollback replayed", got)
	}
}

// Leaving a departed subscriber attached would send an IPMI SOL session's
// output to a browser tab that has already closed.
func TestSerialBrokerStopsDeliveringAfterUnsubscribe(t *testing.T) {
	b, host := newTestBroker(t)

	gone := &recorder{}
	stopGone, err := b.Subscribe(gone)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	staying := &recorder{}
	stopStaying, err := b.Subscribe(staying)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer stopStaying()

	stopGone()

	if _, err := host.Write([]byte("after")); err != nil {
		t.Fatalf("host write: %v", err)
	}
	if !waitFor(t, func() bool { return staying.String() == "after" }) {
		t.Fatalf("remaining subscriber should still receive: %q", staying.String())
	}
	if got := gone.String(); got != "" {
		t.Errorf("unsubscribed consumer received %q, want nothing", got)
	}
}

// One consumer erroring must not deprive the others -- io.MultiWriter aborts on
// the first error, which would let a wedged browser tab mute the SOL session.
func TestSerialBrokerKeepsGoingWhenOneSubscriberFails(t *testing.T) {
	b, host := newTestBroker(t)

	failing := serialFuncWriter(func([]byte) (int, error) {
		return 0, os.ErrClosed
	})
	if _, err := b.Subscribe(failing); err != nil {
		t.Fatalf("subscribe failing: %v", err)
	}

	healthy := &recorder{}
	stopHealthy, err := b.Subscribe(healthy)
	if err != nil {
		t.Fatalf("subscribe healthy: %v", err)
	}
	defer stopHealthy()

	if _, err := host.Write([]byte("still delivered")); err != nil {
		t.Fatalf("host write: %v", err)
	}
	if !waitFor(t, func() bool { return healthy.String() == "still delivered" }) {
		t.Fatalf("healthy subscriber starved by a failing one: %q", healthy.String())
	}
}
