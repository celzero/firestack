// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package dnscrypt

import (
	"errors"
	"strings"

	"github.com/celzero/firestack/intra/xdns"

	"github.com/celzero/firestack/intra/log"
	"github.com/miekg/dns"
)

const (
	ActionNone     = iota // No action has been taken
	ActionContinue        // Continue with the request
	ActionDrop            // Drop the request
	ActionSynth           // Use synthesized response
)

const (
	ReturnCodePass = iota
	ReturnCodeSynth
)

type intercept struct {
	state *interceptstate
}

type interceptstate struct {
	originalMaxPayloadSize           int
	maxUnencryptedUDPSafePayloadSize int
	maxPayloadSize                   int
	question                         *dns.Msg
	qName                            string
	response                         *dns.Msg
	action                           int
	returnCode                       int
	dnssec                           bool
	blocklists                       string
}

// HandleRequest changes the incoming DNS question either to add padding to it or synthesize a pre-determined answer.
func (ic *intercept) handleRequest(msg *dns.Msg) (*dns.Msg, error) {
	state := ic.state
	if len(msg.Question) != 1 {
		return msg, errors.New("unexpected number of questions")
	}
	qName, err := xdns.NormalizeQName(msg.Question[0].Name)
	if err != nil {
		return msg, err
	}
	log.D("dnscrypt: query for [%v]", qName)
	state.qName = qName
	state.question = msg

	// TODO: Recheck: None of these methods return err
	if berr := ic.blockUnqualified(msg); berr != nil {
		state.action = ActionDrop
		return msg, berr
	}
	if serr := ic.getSetPayloadSize(msg); serr != nil {
		state.action = ActionDrop
		return msg, serr
	}
	return msg, nil
}

// handleResponse
func (ic *intercept) handleResponse(packet []byte, truncate bool) ([]byte, error) {
	state := ic.state
	msg := dns.Msg{Compress: true}
	if err := msg.Unpack(packet); err != nil {
		// HasTCFlag is always false because currently transport is TCP only
		if len(packet) >= xdns.MinDNSPacketSize && xdns.HasTCFlag2(packet) {
			log.W("dnscrypt: has-tc-flag, retry with tcp, ignore err: %w", err)
			err = nil
		}
		log.E("dnscrypt: has-tc-flag not set, intercept-handle-response err: %w", err)
		return packet, err
	}

	xdns.RemoveEDNS0Options(&msg)

	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		log.E("dnscrypt: intercept-handle-response err for pack-buffer: %w", err)
		return packet, err
	}

	if truncate && len(packet2) > state.maxUnencryptedUDPSafePayloadSize {
		return xdns.TruncatedResponse(packet2)
	}

	return packet2, nil
}

// GetSetPayloadSize adjusts the maximum payload size advertised in queries sent to upstream servers.
func (ic *intercept) getSetPayloadSize(msg *dns.Msg) error {
	state := ic.state

	if state.action != ActionContinue {
		// nothing to do.
		return nil
	}

	state.originalMaxPayloadSize = 512 - ResponseOverhead
	edns0 := msg.IsEdns0()
	dnssec := false
	if edns0 != nil {
		state.maxUnencryptedUDPSafePayloadSize = int(edns0.UDPSize())
		state.originalMaxPayloadSize = xdns.Max(state.maxUnencryptedUDPSafePayloadSize-ResponseOverhead, state.originalMaxPayloadSize)
		dnssec = edns0.Do()
	}
	var options *[]dns.EDNS0
	state.dnssec = dnssec
	state.maxPayloadSize = xdns.Min(xdns.MaxDNSUDPPacketSize-ResponseOverhead, xdns.Max(state.originalMaxPayloadSize, state.maxPayloadSize))
	if state.maxPayloadSize > 512 {
		extra2 := []dns.RR{}
		for _, extra := range msg.Extra {
			if extra.Header().Rrtype != dns.TypeOPT {
				extra2 = append(extra2, extra)
			} else if xoptions := &extra.(*dns.OPT).Option; len(*xoptions) > 0 && options == nil {
				options = xoptions
			}
		}
		msg.Extra = extra2
		msg.SetEdns0(uint16(state.maxPayloadSize), dnssec)
		if options != nil {
			for _, extra := range msg.Extra {
				if extra.Header().Rrtype == dns.TypeOPT {
					extra.(*dns.OPT).Option = *options
					break
				}
			}
		}
	}
	return nil
}

// BlockUnqualified blocks unqualified DNS names.
func (ic *intercept) blockUnqualified(msg *dns.Msg) error {
	state := ic.state

	if state.action != ActionContinue {
		// nothing to do.
		return nil
	}

	if len(msg.Question) <= 0 {
		return nil
	}

	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	if strings.IndexByte(state.qName, '.') >= 0 {
		return nil
	}
	synth := xdns.EmptyResponseFromMessage(msg) // may be nil
	if synth == nil {
		return nil
	}
	synth.Rcode = dns.RcodeNameError
	state.response = synth
	state.action = ActionSynth
	state.returnCode = ReturnCodeSynth

	return nil
}

func newIntercept() *intercept {
	return &intercept{
		state: newInterceptState(),
	}
}

func newInterceptState() *interceptstate {
	return &interceptstate{
		action:                           ActionContinue,
		returnCode:                       ReturnCodePass,
		maxPayloadSize:                   xdns.MaxDNSUDPPacketSize - ResponseOverhead,
		question:                         nil,
		qName:                            "",
		maxUnencryptedUDPSafePayloadSize: xdns.MaxDNSUDPSafePacketSize,
		dnssec:                           false,
		response:                         nil,
		blocklists:                       "",
	}
}
