package log

import (
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type fconsole struct {
	// takes ownership of w
	w *os.File
}

var _ Console = (*fconsole)(nil)

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

func (f *fconsole) write(msg Logmsg) {
	if len(msg) == 0 {
		return
	}
	for msgline := range strings.SplitSeq(msg, "\n") {
		if len(msgline) <= 0 {
			continue
		}
		if len(msgline) <= charsPerLine {
			f.doWrite(msgline)
		}

		for len(msgline) > 0 {
			m := msgline
			if len(m) > charsPerLine {
				m = m[:charsPerLine]
			}
			if err := f.doWrite(m); err != nil {
				return
			}
			msgline = msgline[len(m):]
		}
	}
}

func (f *fconsole) doWrite(m string) error {
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
