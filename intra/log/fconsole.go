package log

import (
	"bytes"
	"io"
	"os"
	"syscall"
	"unsafe"
)

var newline = []byte{'\n'}

type fconsole struct {
	// takes ownership of w
	w *os.File
}

var _ FilebasedConsole = (*fconsole)(nil)

func newfconsole(w *os.File) *fconsole {
	return &fconsole{w: w}
}

func (p *fconsole) Close() error {
	if w := p.w; w != nil {
		_ = w.Close()
		p.w = nil
	}
	return nil
}

// File returns the underlying os.File. Caller
// must dup() if it intends to use it beyond
// the lifetime of the console.
func (p *fconsole) File() *os.File {
	if p == nil {
		return nil
	}
	return p.w
}

func (p *fconsole) Log(_ LogLevel, msg Logmsg) {
	if p == nil || p.w == nil {
		return
	}
	p.write(msg)
}

func setNonblock(f *os.File) error {
	if f == nil {
		return nil
	}
	return syscall.SetNonblock(int(f.Fd()), true)
}

func (f *fconsole) write(m Logmsg) error {
	if len(m) == 0 {
		return nil
	}

	w := f.w
	if w == nil {
		return io.ErrClosedPipe
	}
	if len(m) <= 0 {
		return nil
	}
	p := unsafe.StringData(m)
	b := unsafe.Slice(p, len(m))
	n, err := w.Write(b)
	// go.dev/play/p/NbJimcpoS0o
	if !bytes.HasSuffix(b, newline) {
		w.Write(newline)
	}
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			// non-blocking write would block; drop the log
			return nil
		}
		return err
	}
	if n < len(m) {
		return io.ErrShortWrite
	}
	return nil
}
