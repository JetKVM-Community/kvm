package kvm

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// A single owner of the CDC-ACM gadget tty, fanning its output out to every
// consumer and merging their input.
//
// There is more than one thing that wants the host's serial console: the WebRTC
// data channel in cdc_acm_console.go, and IPMI SOL. Each opening /dev/ttyGS0
// for itself does not fail and does not warn -- it silently *splits* the
// stream, because every byte a read() returns is a byte the other reader will
// never see. A user watching the browser console and an operator on
// "ipmitool sol activate" would each get a random half of the host's output,
// with nothing anywhere to say why.
//
// That race already existed between two WebRTC sessions before SOL; this
// centralises it rather than adding a third contender.

const serialBrokerDevice = "/dev/ttyGS0"

// serialScrollback is how much recent host output is retained and replayed to a
// newly attached consumer.
//
// Without it a console attaching to an idle host sees nothing at all until the
// host next writes, which on a machine sitting at a shell prompt can be
// indefinitely -- "ipmitool sol activate" looks like it failed. Replaying the
// tail gives the operator the prompt they are already looking at. Borrowed from
// nanokvm-app's serial broker, which took the pattern from tinkerbell/secondstar.
const serialScrollback = 8192

// serialSubscriber receives host output. Write must not block for long: it is
// called on the broker's read loop, and a slow consumer holds up every other
// one. Consumers that can stall should buffer internally.
type serialSubscriber interface {
	io.Writer
}

// subscription identifies one attached consumer.
//
// The set is keyed on this pointer rather than on the serialSubscriber itself
// because a subscriber is an interface value, and Go panics at runtime when the
// dynamic type behind it is not comparable:
//
//	panic: runtime error: hash of unhashable type kvm.serialFuncWriter
//
// A func adapter is the natural way to plug a WebRTC data channel in, and that
// is exactly the shape that blows up. Keying on a pointer accepts any writer.
type subscription struct {
	w serialSubscriber
}

type serialBroker struct {
	mu     sync.Mutex
	file   *os.File
	subs   map[*subscription]struct{}
	closed chan struct{}

	// scroll retains the tail of recent output for replay on attach.
	scroll []byte
}

var (
	cdcSerialBroker   *serialBroker
	cdcSerialBrokerMu sync.Mutex
)

// cdcSerial returns the shared broker for the CDC-ACM gadget, opening the
// device on first use. It stays open while at least one consumer is subscribed.
func cdcSerial() *serialBroker {
	cdcSerialBrokerMu.Lock()
	defer cdcSerialBrokerMu.Unlock()

	if cdcSerialBroker == nil {
		cdcSerialBroker = &serialBroker{subs: map[*subscription]struct{}{}}
	}
	return cdcSerialBroker
}

// Subscribe registers a consumer and returns a function that unsubscribes it.
// The device is opened on the first subscriber and closed after the last one
// leaves, so an idle BMC does not hold the tty open.
func (b *serialBroker) Subscribe(s serialSubscriber) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.file == nil {
		f, err := os.OpenFile(serialBrokerDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", serialBrokerDevice, err)
		}
		b.file = f
		b.closed = make(chan struct{})
		go b.readLoop(f, b.closed)
	}

	sub := &subscription{w: s}
	b.subs[sub] = struct{}{}
	replay := append([]byte(nil), b.scroll...)

	// Outside the lock would be racier, not safer: a write arriving between the
	// replay and the subscribe would be missed entirely. Holding the lock costs
	// one buffered write and guarantees the consumer sees every byte once.
	if len(replay) > 0 {
		_, _ = s.Write(replay)
	}

	return func() { b.unsubscribe(sub) }, nil
}

func (b *serialBroker) unsubscribe(sub *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.subs, sub)
	if len(b.subs) > 0 || b.file == nil {
		return
	}

	// Last one out closes the device. Signalling the read loop first means it
	// stops before the fd is reused by something else.
	close(b.closed)
	b.file.Close()
	b.file = nil
	b.closed = nil
}

// Write sends data to the host. Safe from any goroutine.
func (b *serialBroker) Write(data []byte) (int, error) {
	b.mu.Lock()
	f := b.file
	b.mu.Unlock()

	if f == nil {
		return 0, fmt.Errorf("serial console is not open")
	}
	return f.Write(data)
}

// readLoop is the single reader. Its output is copied to every subscriber, so
// no consumer can consume bytes out from under another.
func (b *serialBroker) readLoop(f *os.File, done chan struct{}) {
	buf := make([]byte, 1024)
	for {
		n, err := f.Read(buf)
		if err != nil {
			select {
			case <-done:
				// Expected: the last subscriber left and closed the device.
			default:
				if err != io.EOF {
					cdcACMLogger.Warn().Err(err).Msg("CDC-ACM read failed; dropping subscribers")
				}
			}
			return
		}

		b.mu.Lock()
		b.scroll = append(b.scroll, buf[:n]...)
		if len(b.scroll) > serialScrollback {
			b.scroll = b.scroll[len(b.scroll)-serialScrollback:]
		}
		subs := make([]*subscription, 0, len(b.subs))
		for s := range b.subs {
			subs = append(subs, s)
		}
		b.mu.Unlock()

		for _, s := range subs {
			// One consumer's failure must not deprive the others of output, so
			// errors are dropped here; consumers detect their own teardown.
			_, _ = s.w.Write(buf[:n])
		}

		select {
		case <-done:
			return
		default:
		}
	}
}

// serialFuncWriter adapts a plain function to serialSubscriber.
type serialFuncWriter func([]byte) (int, error)

func (f serialFuncWriter) Write(p []byte) (int, error) { return f(p) }
