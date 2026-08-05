package kvm

import (
	"sync"

	"github.com/pion/webrtc/v4"
)

// The browser's serial console, as one subscriber of the shared tty rather than
// an owner of it.
//
// This used to os.OpenFile("/dev/ttyGS0") for itself and run its own read loop.
// That is not a second view of the console, it is a second *consumer*: every
// byte read() hands to one reader is a byte no other reader will ever see. Two
// browser tabs already split the host's output between them, and once IPMI SOL
// existed a browser tab left open anywhere would quietly eat the bytes an
// operator on "ipmitool sol activate" was waiting for. Both sides look like a
// console that connects fine and then shows nothing.
//
// serial_broker.go owns the device and fans its output out to every subscriber,
// so opening a console can no longer take one away from someone else.

func handleCDCACMChannel(d *webrtc.DataChannel) {
	scopedLogger := cdcACMLogger.With().
		Uint16("data_channel_id", *d.ID()).Logger()

	var (
		mu    sync.Mutex
		unsub func()
	)

	d.OnOpen(func() {
		// d.Send is not safe to call concurrently with a close, and the broker
		// calls this from its read loop, so the send is what gets guarded --
		// not the device, which the broker serialises already.
		sub := serialFuncWriter(func(p []byte) (int, error) {
			if err := d.Send(p); err != nil {
				return 0, err
			}
			return len(p), nil
		})

		stop, err := cdcSerial().Subscribe(sub)
		if err != nil {
			scopedLogger.Warn().Err(err).Str("path", serialBrokerDevice).
				Msg("Failed to attach to the CDC-ACM console")
			d.Close()
			return
		}

		mu.Lock()
		unsub = stop
		mu.Unlock()

		scopedLogger.Info().Msg("CDC-ACM console channel opened")
	})

	d.OnMessage(func(msg webrtc.DataChannelMessage) {
		// Writes go straight to the broker: unlike reads, concurrent writers
		// interleave rather than steal, and the broker holds the device lock.
		if _, err := cdcSerial().Write(msg.Data); err != nil {
			scopedLogger.Warn().Err(err).Msg("Failed to write to CDC-ACM device")
		}
	})

	d.OnClose(func() {
		mu.Lock()
		stop := unsub
		unsub = nil
		mu.Unlock()

		if stop != nil {
			// Dropping the last subscriber is what closes the device, so an
			// idle BMC does not hold the tty open.
			stop()
		}
		scopedLogger.Info().Msg("CDC-ACM console channel closed")
	})

	d.OnError(func(err error) {
		scopedLogger.Warn().Err(err).Msg("CDC-ACM console channel error")
	})
}
