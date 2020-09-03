package dnscrypt

import (
	"errors"
	"strings"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/k-sone/critbitgo"
	"github.com/miekg/dns"
)

const (
	ActionNone     = iota
	ActionContinue
	ActionDrop
	ActionSynth
)

const (
	ReturnCodePass = iota
	ReturnCodeSynth
)

type ReturnCode int

var ReturnCodeToString = map[ReturnCode]string {
	ReturnCodePass:          "PASS",
	ReturnCodeSynth:         "SYNTH",
}

type Plugin interface {
	HandleRequest([]byte, bool) ([]byte, error)
	HandleResponse([]byte, bool) ([]byte, error)
	getSetPayloadSize(*dns.Msg) error
	blockUnqualified(*dns.Msg) error
	blockUndelegated(*dns.Msg) error
}

type Intercept struct {
	Plugin
	undelegatedSet 			*critbitgo.Trie
	state 					*InterceptState
}

type InterceptState struct {
	originalMaxPayloadSize 				int
	maxUnencryptedUDPSafePayloadSize 	int
	maxPayloadSize 						int
	question 							*dns.Msg
	qName 								string
	response 							*dns.Msg
	action 								int
	returnCode 							int
	dnssec 								bool
}

// HandleRequest changes the incoming DNS question either to add padding to it or synthesize a pre-determined answer.
func (ic *Intercept) HandleRequest(packet []byte, needsEDNS0Padding bool) ([]byte, error) {
	msg := dns.Msg{}
	state := ic.state
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	if len(msg.Question) != 1 {
		return packet, errors.New("Unexpected number of questions")
	}
	qName, err := NormalizeQName(msg.Question[0].Name)
	if err != nil {
		return packet, err
	}
	log.Debugf("Handling query for [%v]", qName)
	state.qName = qName
	state.question = &msg

	// TODO: Recheck: None of these methods return err
	if err := ic.blockUnqualified(&msg); err != nil {
		state.action = ActionDrop
		return packet, err
	}
	if err := ic.blockUndelegated(&msg); err != nil {
		state.action = ActionDrop
		return packet, err
	}
	if err := ic.getSetPayloadSize(&msg); err != nil {
		state.action = ActionDrop
		return packet, err
	}

	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		return packet, err
	}
	if needsEDNS0Padding && state.action == ActionContinue {
		padLen := 63 - ((len(packet2) + 63) & 63)
		if paddedPacket2, _ := addEDNS0PaddingIfNoneFound(&msg, packet2, padLen); paddedPacket2 != nil {
			return paddedPacket2, nil
		}
	}
	return packet2, nil
}

// HandleResponse
func (ic *Intercept) HandleResponse(packet []byte, truncate bool) ([]byte, error) {
	state := ic.state
	msg := dns.Msg{Compress: true}
	if err := msg.Unpack(packet); err != nil {
		// HasTCFlag is mostly false because currently transport is TCP only
		if len(packet) >= MinDNSPacketSize && HasTCFlag(packet) {
			log.Warnf("has-tc-flag, retry with tcp, ignore err: %w", err)
			err = nil
		}
		log.Errorf("has-tc-flag not set, intercept-handle-response err: %w", err)
		return packet, err
	}

	removeEDNS0Options(&msg)

	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		log.Errorf("intercept-handle-response err for pack-buffer: %w", err)
		return packet, err
	}

	if truncate && len(packet2) > state.maxUnencryptedUDPSafePayloadSize {
		return TruncatedResponse(packet2)
	}

	return packet2, nil
}

// GetSetPayloadSize adjusts the maximum payload size advertised in queries sent to upstream servers.
func (ic *Intercept) getSetPayloadSize(msg *dns.Msg) error {
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
		state.originalMaxPayloadSize = Max(state.maxUnencryptedUDPSafePayloadSize-ResponseOverhead, state.originalMaxPayloadSize)
		dnssec = edns0.Do()
	}
	var options *[]dns.EDNS0
	state.dnssec = dnssec
	state.maxPayloadSize = Min(MaxDNSUDPPacketSize-ResponseOverhead, Max(state.originalMaxPayloadSize, state.maxPayloadSize))
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
func (ic *Intercept) blockUnqualified(msg *dns.Msg) error {
	state := ic.state

	if state.action != ActionContinue {
		// nothing to do.
		return nil
	}

	question := msg.Question[0]
	if question.Qclass != dns.ClassINET || (question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return nil
	}
	if strings.IndexByte(state.qName, '.') >= 0 {
		return nil
	}
	synth := EmptyResponseFromMessage(msg)
	synth.Rcode = dns.RcodeNameError
	state.response = synth
	state.action = ActionSynth
	state.returnCode = ReturnCodeSynth

	return nil
}

// BlockUndelegated blocks undelegated DNS names
func (ic *Intercept) blockUndelegated(msg *dns.Msg) error {
	state := ic.state

	if state.action != ActionContinue {
		// nothing to do.
		return nil
	}

	undelegatedSet := ic.undelegatedSet
	revQname := StringReverse(state.qName)
	match, _, found := undelegatedSet.LongestPrefix([]byte(revQname))
	if !found {
		return nil
	}
	if len(match) == len(revQname) || revQname[len(match)] == '.' {
		synth := EmptyResponseFromMessage(msg)
		synth.Rcode = dns.RcodeNameError
		state.response = synth
		state.action = ActionSynth
		state.returnCode = ReturnCodeSynth
	}
	return nil
}

func NewIntercept(set *critbitgo.Trie) *Intercept {
	return &Intercept {
		undelegatedSet: set,
		state: NewInterceptState(),
	}
}

func NewInterceptState() *InterceptState {
	return &InterceptState {
		action:                          	ActionContinue,
		returnCode:                      	ReturnCodePass,
		maxPayloadSize:                  	MaxDNSUDPPacketSize - ResponseOverhead,
		question:                     		nil,
		qName:                           	"",
		maxUnencryptedUDPSafePayloadSize:	MaxDNSUDPSafePacketSize,
		dnssec:							 	false,
		response:                        	nil,
	}
}