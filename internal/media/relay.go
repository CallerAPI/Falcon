package media

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Side names a leg of the bridge. Audio that arrives on SideA is what the
// caller says. Audio that arrives on SideB is what the callee says.
type Side int

const (
	SideA Side = 0
	SideB Side = 1
)

// Tap receives decoded audio as it arrives. pcm is reused after the call
// returns, so a tap that keeps samples must copy them. A tap runs on the
// relay goroutine and must not block.
type Tap interface {
	Audio(side Side, ssrc, timestamp uint32, pcm []int16, at time.Time)
}

// Taps fans audio out to several taps.
type Taps []Tap

func (t Taps) Audio(side Side, ssrc, ts uint32, pcm []int16, at time.Time) {
	for _, tap := range t {
		if tap != nil {
			tap.Audio(side, ssrc, ts, pcm, at)
		}
	}
}

type leg struct {
	sock       *Socket
	remote     atomic.Pointer[net.UDPAddr]
	remoteRTCP atomic.Pointer[net.UDPAddr]
	latched    atomic.Bool
	packets    atomic.Int64
	last       atomic.Int64
	decoders   atomic.Pointer[map[uint8]Decoder]
}

// Relay moves RTP and RTCP between two legs. Packets that arrive on one
// leg's socket leave from the other leg's socket toward that leg's far
// end. The far end is the address from its SDP until its first packet
// arrives, and then the address that packet came from.
type Relay struct {
	legs    [2]*leg
	tap     Tap
	wg      sync.WaitGroup
	closing atomic.Bool
}

// NewRelay pairs two sockets. tap may be nil.
func NewRelay(a, b *Socket, tap Tap) *Relay {
	return &Relay{legs: [2]*leg{{sock: a}, {sock: b}}, tap: tap}
}

// SetRemote points a leg at its far end. A new address resets latching,
// which is what a re-INVITE with new media needs.
func (r *Relay) SetRemote(side Side, host string, port int) error {
	if port <= 0 {
		return errors.New("media: no remote port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return errors.New("media: remote host does not resolve")
		}
		ip = addrs[0]
	}
	l := r.legs[side]
	rtp := &net.UDPAddr{IP: ip, Port: port}
	if cur := l.remote.Load(); cur != nil && cur.IP.Equal(rtp.IP) && cur.Port == rtp.Port {
		return nil
	}
	l.remote.Store(rtp)
	l.remoteRTCP.Store(&net.UDPAddr{IP: ip, Port: port + 1})
	l.latched.Store(false)
	return nil
}

// SetCodecs tells the relay how to decode audio that arrives on a side.
func (r *Relay) SetCodecs(side Side, codecs map[uint8]string) {
	dec := map[uint8]Decoder{}
	for pt, name := range codecs {
		if d := DecoderFor(name); d != nil {
			dec[pt] = d
		}
	}
	r.legs[side].decoders.Store(&dec)
}

// Start runs the four relay loops.
func (r *Relay) Start() {
	for side := SideA; side <= SideB; side++ {
		r.wg.Add(2)
		go r.rtpLoop(side)
		go r.rtcpLoop(side)
	}
}

// Close stops the loops. The sockets are released by their allocator.
func (r *Relay) Close() {
	if !r.closing.CompareAndSwap(false, true) {
		return
	}
	for _, l := range r.legs {
		l.sock.Close()
	}
	r.wg.Wait()
}

// Packets counts RTP packets that arrived on a side.
func (r *Relay) Packets(side Side) int64 { return r.legs[side].packets.Load() }

// LastPacket is when audio last arrived on either side. Zero is never.
func (r *Relay) LastPacket() time.Time {
	a, b := r.legs[SideA].last.Load(), r.legs[SideB].last.Load()
	if b > a {
		a = b
	}
	if a == 0 {
		return time.Time{}
	}
	return time.Unix(0, a)
}

// Port is the local RTP port of a side.
func (r *Relay) Port(side Side) int { return r.legs[side].sock.Port }

func (r *Relay) rtpLoop(side Side) {
	defer r.wg.Done()
	in, out := r.legs[side], r.legs[1-side]
	buf := make([]byte, 2048)
	pcm := make([]int16, 0, 960)
	for {
		n, from, err := in.sock.RTP.ReadFromUDP(buf)
		if err != nil {
			return
		}
		now := time.Now()
		in.last.Store(now.UnixNano())
		in.packets.Add(1)
		latch(&in.remote, &in.latched, from)
		if dst := out.remote.Load(); dst != nil {
			_, _ = out.sock.RTP.WriteToUDP(buf[:n], dst)
		}
		if r.tap == nil || isRTCP(buf[:n]) {
			continue
		}
		p, ok := ParseRTP(buf[:n])
		if !ok {
			continue
		}
		decs := in.decoders.Load()
		if decs == nil {
			continue
		}
		if dec := (*decs)[p.PayloadType]; dec != nil {
			pcm = dec(pcm[:0], p.Payload)
			r.tap.Audio(side, p.SSRC, p.Timestamp, pcm, now)
		}
	}
}

func (r *Relay) rtcpLoop(side Side) {
	defer r.wg.Done()
	in, out := r.legs[side], r.legs[1-side]
	buf := make([]byte, 2048)
	var latched atomic.Bool
	for {
		n, from, err := in.sock.RTCP.ReadFromUDP(buf)
		if err != nil {
			return
		}
		latch(&in.remoteRTCP, &latched, from)
		if dst := out.remoteRTCP.Load(); dst != nil {
			_, _ = out.sock.RTCP.WriteToUDP(buf[:n], dst)
		}
	}
}

// latch takes the source of the first packet as the far end when it
// differs from the SDP address. That is symmetric RTP through NAT.
func latch(remote *atomic.Pointer[net.UDPAddr], latched *atomic.Bool, from *net.UDPAddr) {
	if from == nil || latched.Load() {
		return
	}
	cur := remote.Load()
	if cur == nil || !cur.IP.Equal(from.IP) || cur.Port != from.Port {
		remote.Store(&net.UDPAddr{IP: append(net.IP(nil), from.IP...), Port: from.Port})
	}
	latched.Store(true)
}

// HostPort formats an address for SDP and logs.
func HostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
