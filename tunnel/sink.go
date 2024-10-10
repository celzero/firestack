// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tunnel

import (
	"context"
	"io"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/netstack"
)

type pcapsink struct {
	ctx  context.Context
	done context.CancelFunc
	sink *core.Volatile[io.WriteCloser]
	inC  chan []byte // always buffered
}

// nowrite rejects all writes.
type nowrite struct{}

var _ io.WriteCloser = (*nowrite)(nil)
var _ io.WriteCloser = (*pcapsink)(nil)

func (*nowrite) Write(b []byte) (int, error) { return len(b), nil }
func (*nowrite) Close() error                { return nil }

func newSink(pctx context.Context) *pcapsink {
	ctx, cancel := context.WithCancel(pctx)
	// go.dev/play/p/4qANL9VSDXb
	p := new(pcapsink)
	p.ctx = ctx
	p.done = cancel
	p.sink = core.NewVolatile[io.WriteCloser](zerowriter)
	p.log(false)  // no log
	p.fout(false) // no file out
	p.inC = make(chan []byte, 128)
	core.Go("pcap.w", func() { p.writeAsync() })
	context.AfterFunc(ctx, func() {
		defer close(p.inC) // signal writeAsync to exit
		p.recycle()
	})
	return p
}

func (p *pcapsink) Write(b []byte) (int, error) {
	select {
	case <-p.ctx.Done(): // closed
	default:
		select {
		case <-p.ctx.Done(): // closed
		case p.inC <- b:
			return len(b), nil
		default: // drop
			return len(b), nil
		}
	}
	return 0, io.ErrClosedPipe // err here may panic netstack's sniffer
}

// writeAsync consumes [p.in] until close.
func (p *pcapsink) writeAsync() {
	for b := range p.inC { // winsy spider
		w := p.sink.Load() // always re-load current writer
		if w != nil && w != zerowriter {
			n, err := w.Write(b)
			log.VV("tun: pcap: writeAsync: n: %d, err? %v", n, err)
		} // else: no op
	}
}

func (p *pcapsink) recycle() error {
	p.log(false)       // detach
	err := p.file(nil) // detach
	return err
}

func (p *pcapsink) Close() error {
	p.done()
	return nil
}

func (p *pcapsink) file(f io.WriteCloser) (err error) {
	if f == nil || core.IsNil(f) {
		f = zerowriter
	}

	old := p.sink.Tango(f) // old may be nil
	core.CloseOp(old, core.CopRW)

	y := f != zerowriter
	if y {
		// from: github.com/google/gvisor/blob/596e8d22/pkg/tcpip/link/sniffer/sniffer.go#L93
		err = netstack.WritePCAPHeader(f) // write pcap header before any packets
		log.I("tun: pcap: begin: writeHeader; err(%v)", err)
	}
	p.fout(y)
	return
}

func (p *pcapsink) log(y bool) bool {
	return netstack.LogPcap(y)
}

func (p *pcapsink) fout(y bool) bool {
	return netstack.LogFile(y)
}
