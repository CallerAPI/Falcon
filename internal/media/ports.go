package media

import (
	"errors"
	"net"
	"strconv"
	"sync"
)

// Socket is one RTP port and the RTCP port above it.
type Socket struct {
	Port int
	RTP  *net.UDPConn
	RTCP *net.UDPConn
}

// Close releases both ports.
func (s *Socket) Close() {
	if s == nil {
		return
	}
	if s.RTP != nil {
		_ = s.RTP.Close()
	}
	if s.RTCP != nil {
		_ = s.RTCP.Close()
	}
}

// Allocator hands out even RTP ports from a range. A port another process
// holds is skipped.
type Allocator struct {
	bind string
	min  int
	max  int

	mu   sync.Mutex
	next int
	used map[int]struct{}
}

// ErrNoPorts means every port in the range is in use.
var ErrNoPorts = errors.New("media: no free RTP port")

// NewAllocator binds on bind (empty is every interface) between min and max.
func NewAllocator(bind string, min, max int) *Allocator {
	if min%2 == 1 {
		min++
	}
	return &Allocator{bind: bind, min: min, max: max, next: min, used: map[int]struct{}{}}
}

// Capacity is how many sockets the range holds.
func (a *Allocator) Capacity() int { return (a.max - a.min + 1) / 2 }

// InUse is how many sockets are out.
func (a *Allocator) InUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}

// Allocate binds the next free pair.
func (a *Allocator) Allocate() (*Socket, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	tries := a.Capacity()
	for i := 0; i < tries; i++ {
		port := a.next
		a.next += 2
		if a.next+1 > a.max {
			a.next = a.min
		}
		if _, busy := a.used[port]; busy {
			continue
		}
		rtp, err := listenUDP(a.bind, port)
		if err != nil {
			continue
		}
		rtcp, err := listenUDP(a.bind, port+1)
		if err != nil {
			_ = rtp.Close()
			continue
		}
		a.used[port] = struct{}{}
		return &Socket{Port: port, RTP: rtp, RTCP: rtcp}, nil
	}
	return nil, ErrNoPorts
}

// Release closes the pair and returns its port to the range.
func (a *Allocator) Release(s *Socket) {
	if s == nil {
		return
	}
	s.Close()
	a.mu.Lock()
	delete(a.used, s.Port)
	a.mu.Unlock()
}

func listenUDP(host string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}
