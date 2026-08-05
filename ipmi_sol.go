package kvm

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/bougou/go-ipmi/pkg/bmc"
	"github.com/bougou/go-ipmi/pkg/crypto"
	"github.com/bougou/go-ipmi/pkg/handlers"
	"github.com/bougou/go-ipmi/pkg/protocol"
	"github.com/bougou/go-ipmi/pkg/transport"
	"github.com/bougou/go-ipmi/pkg/types"
)

// Serial Over LAN (IPMI v2.0 §15.9, §24, §26.11) carried to the host over the
// CDC-ACM gadget.
//
// go-ipmi's server cannot do this itself. Its RMCP+ dispatch handles only the
// session-setup payload types and PayloadTypeIPMI; a SOL payload (0x01) falls
// off the end of that switch and is dropped, and there are no Activate Payload
// handlers. The switch is unexported, so it cannot be extended from here.
//
// What *is* reachable is the transport: NewServer takes a transport.PacketConn,
// a three-method interface. Wrapping it puts this code ahead of the dispatch
// switch -- SOL payloads are handled and swallowed, everything else is passed
// through untouched. The session keys needed to decrypt them are exported
// (bmc.SessionStore.Get, and Session.K2), as are the packet helpers, so this
// needs no fork.
//
// Activate/Deactivate Payload are ordinary IPMI commands and go through the
// normal handler registry.

const (
	// solPayloadType is the RMCP+ payload type for SOL (v2.0 Table 13-16).
	solPayloadType uint8 = 0x01

	// SOL character data starts after a 4-byte header in both directions
	// (v2.0 Table 15-2).
	solHeaderLen = 4

	// solMaxOutbound bounds a single BMC->console packet's character payload.
	// Chosen to stay clear of the 576-byte IPv4 minimum MTU once RMCP+, session
	// and integrity overhead are added, so a console session never depends on
	// fragmentation working.
	solMaxOutbound = 240

	// Command numbers within netFn App (0x06), v2.0 §24.
	cmdActivatePayload            uint8 = 0x48
	cmdDeactivatePayload          uint8 = 0x49
	cmdGetPayloadActivationStatus uint8 = 0x4A

	// RMCP+ packet layout, needed because the integrity trailer has to be
	// produced and checked here. go-ipmi has both routines already
	// (server/integrity.go) but they are unexported; everything they are built
	// from is not, so these mirror them rather than fork the package. The sizes
	// are fixed by the wire format: a 4-byte RMCP header and a 12-byte RMCP+
	// session header ahead of the payload.
	rmcpHeaderSize        = 4
	rmcpPlusHeaderSize    = 12
	rmcpPlusPayloadOffset = rmcpHeaderSize + rmcpPlusHeaderSize
	rmcpPlusNextHeader    = 0x07 // v2.0 Table 13-8
)

// solSession is one activated SOL payload: which RMCP+ session carries it,
// where to send, and the sequence state for the console<->BMC stream.
type solSession struct {
	mu sync.Mutex

	sessionID uint32 // BMC-assigned session ID
	addr      net.Addr

	// outSeq is this BMC's packet sequence number, 1..15 and never 0 -- 0 means
	// "no data, ACK only" (v2.0 §15.9.2), so using it for real data would make
	// the console discard the characters.
	outSeq uint8

	// lastInSeq is the last console sequence accepted, for detecting the
	// retries the console sends when it does not see an ACK.
	lastInSeq uint8

	unsubscribe func()
	active      bool
}

var (
	solMu      sync.Mutex
	solCurrent *solSession

	// solTransport is the wrapped connection the active server is reading from.
	// Host output arrives on the serial broker's goroutine, which has no route
	// back to the server, so the transport is recorded when the server is built.
	solTransportMu sync.Mutex
	solTransport   *solConn

	// solSendMu serialises SOL sends; see solSend.
	solSendMu sync.Mutex

	// solPeers maps a session to the address it last spoke from. Bounded by the
	// session store's own limit, and entries are dropped with their session.
	solPeerMu sync.Mutex
	solPeers  = map[uint32]net.Addr{}
)

func solRecordPeer(sessionID uint32, addr net.Addr) {
	solPeerMu.Lock()
	solPeers[sessionID] = addr
	solPeerMu.Unlock()
}

func solPeer(sessionID uint32) net.Addr {
	solPeerMu.Lock()
	defer solPeerMu.Unlock()
	return solPeers[sessionID]
}

func solForgetPeer(sessionID uint32) {
	solPeerMu.Lock()
	delete(solPeers, sessionID)
	solPeerMu.Unlock()
}

// newSOLConn wraps a transport for SOL and records it for the send path.
func newSOLConn(conn transport.PacketConn, b *bmc.BMC) *solConn {
	c := &solConn{PacketConn: conn, b: b}

	solTransportMu.Lock()
	solTransport = c
	solTransportMu.Unlock()

	return c
}

// solShutdown drops the recorded transport and any active console. Called when
// the IPMI server stops, so a restarted server never sends on the old socket.
func solShutdown() {
	solTransportMu.Lock()
	solTransport = nil
	solTransportMu.Unlock()

	solMu.Lock()
	s := solCurrent
	solCurrent = nil
	solMu.Unlock()

	if s == nil {
		return
	}
	s.mu.Lock()
	s.active = false
	unsub := s.unsubscribe
	s.mu.Unlock()
	if unsub != nil {
		unsub()
	}
}

// solConn wraps the UDP transport so SOL payloads can be handled before
// go-ipmi's dispatch switch discards them.
type solConn struct {
	transport.PacketConn
	b *bmc.BMC
}

// ReadFrom passes non-SOL packets through. A SOL packet is handled here and the
// read is retried, so the wrapped server never sees it and cannot be confused
// by a payload type it has no case for.
func (c *solConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return n, addr, err
		}

		sessionID, _, payloadType, _, _, ok := protocol.ParseRMCPPlusHeader(buf[:n])
		if ok && sessionID != 0 {
			// Note where this session is talking from, whatever the payload.
			// Activate Payload arrives as an ordinary IPMI command and carries
			// no address a handler can see, so without this the BMC has nowhere
			// to send host output until the console happens to send a SOL packet
			// of its own -- which presents as a console that attaches and then
			// shows nothing.
			solRecordPeer(sessionID, addr)
		}

		if !ok || payloadType != solPayloadType {
			return n, addr, nil
		}

		c.handleSOL(addr, buf[:n])
		// Consumed: loop for the next packet rather than returning 0 bytes,
		// which the server would read as a malformed datagram.
	}
}

// handleSOL applies one inbound SOL payload.
func (c *solConn) handleSOL(addr net.Addr, pkt []byte) {
	sessionID, inboundSeq, _, flags, payload, ok := protocol.ParseRMCPPlusHeader(pkt)
	if !ok {
		return
	}

	sess, err := c.b.Sessions.Get(sessionID)
	if err != nil {
		// A SOL payload for a session we do not have is not ours to answer.
		return
	}

	// Everything below this point ends up as keystrokes on the managed host's
	// console, so the same checks go-ipmi applies to a session's IPMI payloads
	// apply here. Skipping them would let anyone who can reach the port and
	// guess a session ID type at a root shell.
	if !solVerifyIntegrity(pkt, sess, flags&protocol.PayloadAuthenticatedFlag != 0) {
		ipmiLogger.Debug().Msg("SOL payload failed its integrity check")
		return
	}
	if !bmc.InboundSeqValid(sess.InboundSeq, inboundSeq) {
		return
	}
	sess.InboundSeq = inboundSeq

	if flags&protocol.PayloadEncryptedFlag != 0 {
		decrypted, err := crypto.DecryptAESPayload(payload, sess.K2)
		if err != nil {
			ipmiLogger.Debug().Err(err).Msg("SOL payload failed to decrypt")
			return
		}
		payload = decrypted
	}

	solConsoleToHost(addr, sessionID, payload)
}

// solConsoleToHost applies one console->BMC SOL packet: the characters go to
// the host, and the packet is acknowledged so the console stops retrying.
func solConsoleToHost(addr net.Addr, sessionID uint32, payload []byte) {
	if len(payload) < solHeaderLen {
		return
	}

	seq := payload[0] & 0x0f
	data := payload[solHeaderLen:]

	solMu.Lock()
	s := solCurrent
	solMu.Unlock()
	if s == nil || !s.active || s.sessionID != sessionID {
		return
	}

	s.mu.Lock()
	retry := seq != 0 && seq == s.lastInSeq
	if seq != 0 {
		s.lastInSeq = seq
	}
	s.addr = addr
	s.mu.Unlock()

	// A repeated sequence number is the console resending because it missed the
	// ACK. Writing the characters again would duplicate the operator's
	// keystrokes, so re-acknowledge without replaying them.
	if len(data) > 0 && !retry {
		if _, err := cdcSerial().Write(data); err != nil {
			ipmiLogger.Debug().Err(err).Msg("SOL write to the host failed")
		}
	}

	if seq != 0 {
		s.sendPacket(0, seq, uint8(len(data)), nil)
	}
}

// sendPacket emits one BMC->console SOL packet. ackSeq/accepted acknowledge the
// console's last packet; data carries host output.
func (s *solSession) sendPacket(seq, ackSeq, accepted uint8, data []byte) {
	s.mu.Lock()
	addr := s.addr
	sessionID := s.sessionID
	s.mu.Unlock()

	if addr == nil {
		return
	}

	payload := make([]byte, solHeaderLen+len(data))
	payload[0] = seq
	payload[1] = ackSeq
	payload[2] = accepted
	payload[3] = 0 // no break, no status conditions
	copy(payload[solHeaderLen:], data)

	solSend(addr, sessionID, payload)
}

// solSend wraps a SOL payload in an RMCP+ session packet and puts it on the
// wire, encrypting and signing it exactly as the session negotiated.
//
// This is what go-ipmi's sendRMCPPlusSession does for its own responses; it is
// a method on the unexported Server, so it is rebuilt here from the exported
// pieces rather than reached.
func solSend(addr net.Addr, sessionID uint32, payload []byte) {
	solTransportMu.Lock()
	c := solTransport
	solTransportMu.Unlock()

	if c == nil || addr == nil {
		return
	}

	sess, err := c.b.Sessions.Get(sessionID)
	if err != nil {
		return
	}

	// One SOL packet at a time: this runs on the serial broker's read loop as
	// well as on the IPMI read loop, and the two would otherwise interleave
	// their reads of the session's outbound sequence number.
	//
	// It does not cover the *other* writer. go-ipmi increments the same counter
	// from its own goroutine when it answers an IPMI command, with no lock, and
	// bmc.Session exposes none to borrow -- so a SOL packet and an IPMI response
	// racing can lose an increment and reuse a sequence number. The window is
	// narrow (a session carrying SOL sends little else but keepalives) and the
	// cost is one packet the console discards as a duplicate and the SOL layer
	// retries. The real fix belongs in go-ipmi, as a Session method that hands
	// out sequence numbers under the session's own lock.
	solSendMu.Lock()
	defer solSendMu.Unlock()

	flags := uint8(0)
	if sess.CryptAlg != types.CryptAlg_None && len(sess.K2) >= 16 {
		enc, err := crypto.EncryptAESPayload(payload, sess.K2, crypto.RandomBytes(16))
		if err != nil {
			return
		}
		payload = enc
		flags |= protocol.PayloadEncryptedFlag
	}
	if sess.IntegrityAlg != types.IntegrityAlg_None {
		flags |= protocol.PayloadAuthenticatedFlag
	}

	sess.OutboundSeq++
	pkt := protocol.BuildRMCPPlusPacket(solPayloadType, flags, sess.ConsoleID, sess.OutboundSeq, payload)

	pkt, ok := solAppendIntegrity(pkt, sess)
	if !ok {
		return
	}
	if _, err := c.WriteTo(pkt, addr); err != nil {
		ipmiLogger.Debug().Err(err).Msg("SOL send failed")
	}
}

// solAppendIntegrity adds the RMCP+ integrity pad and auth code, mirroring
// go-ipmi's unexported appendRMCPPlusIntegrity.
func solAppendIntegrity(pkt []byte, sess *bmc.Session) ([]byte, bool) {
	authCodeLen, ok := crypto.IntegrityAuthCodeLen(sess.IntegrityAlg)
	if !ok {
		return nil, false
	}
	if authCodeLen == 0 {
		// No integrity negotiated: the packet is complete as it stands.
		return pkt, true
	}
	if len(sess.K1) == 0 || len(pkt) < rmcpPlusPayloadOffset {
		return nil, false
	}

	// The pad brings session header + payload + the two trailer bytes to a
	// multiple of four (v2.0 §13.29).
	padLen := types.IntegrityPadLen(rmcpPlusHeaderSize, len(pkt)-rmcpPlusPayloadOffset)
	out := make([]byte, 0, len(pkt)+padLen+2+authCodeLen)
	out = append(out, pkt...)
	for i := 0; i < padLen; i++ {
		out = append(out, 0xff)
	}
	out = append(out, byte(padLen), rmcpPlusNextHeader)

	// The auth code covers everything from the session header onward -- the RMCP
	// header itself is excluded.
	authCode, err := crypto.SessionIntegrityAuthCode(sess.IntegrityAlg, out[rmcpHeaderSize:], sess.K1, "")
	if err != nil || len(authCode) != authCodeLen {
		return nil, false
	}
	return append(out, authCode...), true
}

// solVerifyIntegrity checks an inbound packet's auth code, mirroring go-ipmi's
// unexported verifyRMCPPlusIntegrity.
func solVerifyIntegrity(pkt []byte, sess *bmc.Session, authenticated bool) bool {
	authCodeLen, ok := crypto.IntegrityAuthCodeLen(sess.IntegrityAlg)
	if !ok {
		return false
	}
	if authCodeLen == 0 {
		// The session negotiated no integrity. Cipher suite 0 would land here,
		// which is why ipmiCipherSuites does not offer it.
		return true
	}
	if !authenticated || len(sess.K1) == 0 || len(pkt) < rmcpPlusPayloadOffset {
		return false
	}

	payloadLen := int(binary.LittleEndian.Uint16(pkt[14:16]))
	payloadEnd := rmcpPlusPayloadOffset + payloadLen
	if len(pkt) < payloadEnd {
		return false
	}

	padLen := types.IntegrityPadLen(rmcpPlusHeaderSize, payloadLen)
	authCodeStart := payloadEnd + padLen + 2
	if len(pkt) != authCodeStart+authCodeLen {
		return false
	}
	for _, b := range pkt[payloadEnd : payloadEnd+padLen] {
		if b != 0xff {
			return false
		}
	}
	if pkt[payloadEnd+padLen] != byte(padLen) || pkt[payloadEnd+padLen+1] != rmcpPlusNextHeader {
		return false
	}

	expected, err := crypto.SessionIntegrityAuthCode(sess.IntegrityAlg, pkt[rmcpHeaderSize:authCodeStart], sess.K1, "")
	if err != nil {
		return false
	}
	// crypto.Equal is constant-time.
	return crypto.Equal(expected, pkt[authCodeStart:])
}

// Write is the subscriber side: host output becomes SOL packets.
func (s *solSession) Write(p []byte) (int, error) {
	written := len(p)

	for len(p) > 0 {
		chunk := p
		if len(chunk) > solMaxOutbound {
			chunk = chunk[:solMaxOutbound]
		}

		s.mu.Lock()
		// 1..15: sequence 0 is reserved for ACK-only packets.
		s.outSeq++
		if s.outSeq > 0x0f {
			s.outSeq = 1
		}
		seq := s.outSeq
		s.mu.Unlock()

		s.sendPacket(seq, 0, 0, chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// solActivate starts a SOL session for the given RMCP+ session.
func solActivate(sessionID uint32) error {
	// Reap an abandoned console first.
	//
	// A console that goes away without sending Deactivate Payload -- killed,
	// disconnected, or timed out -- leaves this state marked active forever,
	// holding the tty open and answering every later operator with "payload
	// already active" on behalf of a session that no longer exists. Checking at
	// the moment someone tries to attach is both the cheapest place to notice
	// and the only place the answer matters.
	if stale := solStaleSession(sessionID); stale != 0 {
		ipmiLogger.Info().Uint32("session", stale).
			Msg("reaping a SOL console whose IPMI session is gone")
		solDeactivate(stale)
	}

	solMu.Lock()
	defer solMu.Unlock()

	if solCurrent != nil && solCurrent.active {
		// One console at a time. Two would interleave keystrokes into one tty
		// with no way for either operator to tell.
		return errSOLAlreadyActive
	}

	// The console's address is already known from the packet that carried this
	// very command, so host output can flow before it sends any SOL of its own.
	s := &solSession{sessionID: sessionID, active: true, addr: solPeer(sessionID)}
	unsub, err := cdcSerial().Subscribe(s)
	if err != nil {
		return err
	}
	s.unsubscribe = unsub
	solCurrent = s

	ipmiLogger.Info().Uint32("session", sessionID).Msg("SOL activated")
	return nil
}

// solStaleSession returns the session ID of an active console whose RMCP+
// session has gone away, or 0. A console re-activating on its own session
// counts as stale too: that is a client that restarted, and refusing it would
// lock out the one operator entitled to be there.
func solStaleSession(incoming uint32) uint32 {
	solMu.Lock()
	s := solCurrent
	solMu.Unlock()

	if s == nil || !s.active {
		return 0
	}
	if s.sessionID == incoming {
		return s.sessionID
	}

	solTransportMu.Lock()
	c := solTransport
	solTransportMu.Unlock()
	if c == nil {
		return s.sessionID
	}

	// Expiry is otherwise only evaluated when the store is next touched, so an
	// idle session can outlive its timeout in the map.
	c.b.Sessions.EvictExpired()
	if _, err := c.b.Sessions.Get(s.sessionID); err != nil {
		return s.sessionID
	}
	return 0
}

// solDeactivate tears down the active SOL session.
func solDeactivate(sessionID uint32) {
	solMu.Lock()
	s := solCurrent
	if s == nil || s.sessionID != sessionID {
		solMu.Unlock()
		return
	}
	solCurrent = nil
	solMu.Unlock()

	solForgetPeer(sessionID)

	s.mu.Lock()
	s.active = false
	unsub := s.unsubscribe
	s.mu.Unlock()

	if unsub != nil {
		unsub()
	}
	ipmiLogger.Info().Uint32("session", sessionID).Msg("SOL deactivated")
}

// solRegisterHandlers adds the payload commands go-ipmi does not implement.
func solRegisterHandlers(r *handlers.Registry) {
	r.RegisterFunc(
		types.Command{NetFn: types.NetFnAppRequest, ID: cmdActivatePayload},
		handleActivatePayload,
	)
	r.RegisterFunc(
		types.Command{NetFn: types.NetFnAppRequest, ID: cmdDeactivatePayload},
		handleDeactivatePayload,
	)
	r.RegisterFunc(
		types.Command{NetFn: types.NetFnAppRequest, ID: cmdGetPayloadActivationStatus},
		handleGetPayloadActivationStatus,
	)
}

// errSOLAlreadyActive is returned when a second console tries to activate SOL.
var errSOLAlreadyActive = fmt.Errorf("SOL is already active on another session")

// handleActivatePayload implements Activate Payload (v2.0 §24.1).
//
// Request:  [0] payload type (bits 5:0), [1] instance, [2..5] aux data
// Response: [0..3] aux data, [4..5] inbound max, [6..7] outbound max,
//
//	[8..9] UDP port, [10..11] VLAN (FFFFh = none)
func handleActivatePayload(
	_ context.Context, hctx *handlers.HandlerContext, data []byte,
) ([]byte, types.CompletionCode, error) {
	if len(data) < 6 {
		return nil, types.CodeRequestDataLengthInvalid, nil
	}
	if data[0]&0x3f != solPayloadType {
		// Only SOL is offered; claiming otherwise would have a console wait for
		// a payload that never arrives.
		return nil, types.CodeRequestDataFieldInvalid, nil
	}
	if hctx.Session == nil {
		return nil, types.CodeInsufficientPrivilege, nil
	}

	if err := solActivate(hctx.Session.BMCID); err != nil {
		// 80h in this command's context is "payload already active".
		return nil, types.CompletionCode(0x80), nil
	}

	resp := make([]byte, 12)
	// Aux data echoes as zero: no test mode, no encryption negotiated beyond
	// what the session already provides.
	resp[4] = byte(solMaxOutbound)  // inbound size, LSB
	resp[5] = 0                     //             MSB
	resp[6] = byte(solMaxOutbound)  // outbound size, LSB
	resp[7] = 0                     //              MSB
	resp[8] = byte(ipmiPort & 0xff) // UDP port, LSB
	resp[9] = byte(ipmiPort >> 8)
	resp[10] = 0xff // no VLAN
	resp[11] = 0xff
	return resp, types.CodeOK, nil
}

// handleDeactivatePayload implements Deactivate Payload (v2.0 §24.2).
func handleDeactivatePayload(
	_ context.Context, hctx *handlers.HandlerContext, data []byte,
) ([]byte, types.CompletionCode, error) {
	if len(data) < 6 {
		return nil, types.CodeRequestDataLengthInvalid, nil
	}
	if data[0]&0x3f != solPayloadType {
		return nil, types.CodeRequestDataFieldInvalid, nil
	}
	if hctx.Session != nil {
		solDeactivate(hctx.Session.BMCID)
	}
	return nil, types.CodeOK, nil
}

// handleGetPayloadActivationStatus implements v2.0 §24.4. ipmitool calls this
// before activating, and a wrong answer here makes it refuse to start.
func handleGetPayloadActivationStatus(
	_ context.Context, _ *handlers.HandlerContext, data []byte,
) ([]byte, types.CompletionCode, error) {
	if len(data) < 1 {
		return nil, types.CodeRequestDataLengthInvalid, nil
	}
	if data[0] != solPayloadType {
		return nil, types.CodeRequestDataFieldInvalid, nil
	}

	solMu.Lock()
	active := solCurrent != nil && solCurrent.active
	solMu.Unlock()

	// [0] instance capacity, [1..2] bitmask of active instances.
	resp := []byte{1, 0, 0}
	if active {
		resp[1] = 0x01 // instance 1 in use
	}
	return resp, types.CodeOK, nil
}
