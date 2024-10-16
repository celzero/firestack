package protect

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
)

// The fake protector just records the file descriptors it was given.
type fakeProtector struct {
	mu  sync.Mutex
	fds []int32
}

// Implements Protector.
func (p *fakeProtector) UIP(n string) []byte {
	return net.IPv4(127, 0, 0, 1)
}

func (p *fakeProtector) Protect(fd int32) bool {
	p.mu.Lock()
	p.fds = append(p.fds, fd)
	p.mu.Unlock()
	return true
}

func (p *fakeProtector) GetResolvers() string {
	return "8.8.8.8,2001:4860:4860::8888"
}

// This interface serves as a supertype of net.TCPConn and net.UDPConn, so
// that they can share the verifyMatch() function.
type hasSyscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func verifyMatch(t *testing.T, conn hasSyscallConn, p *fakeProtector) {
	rawconn, err := conn.SyscallConn()
	if err != nil || rawconn == nil {
		t.Fatal(errors.Join(err, &net.OpError{Op: "SyscallConn"}))
	}
	_ = rawconn.Control(func(fd uintptr) {
		if len(p.fds) == 0 {
			t.Fatalf("No file descriptors")
		}
		if int32(fd) != p.fds[0] {
			t.Fatalf("File descriptor mismatch: %d != %d", fd, p.fds[0])
		}
	})
}

func TestDialTCP(t *testing.T) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go l.Accept()

	p := &fakeProtector{}
	d := MakeDialer(p)
	if d.Control == nil {
		t.Errorf("Control function is nil")
	}

	conn, err := d.Dial("tcp", l.Addr().String())
	if err != nil || conn == nil {
		t.Fatal(errors.Join(err, &net.OpError{Op: "Dial"}))
		return
	}
	verifyMatch(t, conn.(*net.TCPConn), p)
	clos(conn)
	clos(l)
}

func TestListenUDP(t *testing.T) {
	udpaddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	p := &fakeProtector{}
	c := MakeListenConfig(p)

	conn, err := c.ListenPacket(context.Background(), udpaddr.Network(), udpaddr.String())
	if err != nil || conn == nil {
		t.Fatal(errors.Join(err, &net.OpError{Op: "ListenPacket"}))
		return
	}
	verifyMatch(t, conn.(*net.UDPConn), p)
	clos(conn)
}

func TestLookupIPAddr(t *testing.T) {
	p := &fakeProtector{}
	d := MakeDialer(p)
	d.Resolver.LookupIPAddr(context.Background(), "foo.test.")
	// Verify that Protect was called.
	if len(p.fds) == 0 {
		t.Fatal("Protect was not called")
	}
}

func TestNilDialer(t *testing.T) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go l.Accept()

	d := MakeDialer(nil)
	conn, err := d.Dial("tcp", l.Addr().String())
	if err != nil || conn == nil {
		t.Fatal(errors.Join(err, &net.OpError{Op: "Dial"}))
		return
	}

	clos(conn)
	clos(l)
}

func TestNilListener(t *testing.T) {
	udpaddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	c := MakeListenConfig(nil)
	conn, err := c.ListenPacket(context.Background(), udpaddr.Network(), udpaddr.String())
	if err != nil || conn == nil {
		t.Fatal(errors.Join(err, &net.OpError{Op: "Dial"}))
	}

	clos(conn)
}
