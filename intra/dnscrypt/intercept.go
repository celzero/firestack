package dnscrypt

import (
	"errors"
	"strings"

	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/dnsx"
	"github.com/Jigsaw-Code/outline-go-tun2socks/intra/xdns"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/k-sone/critbitgo"
	"github.com/miekg/dns"
)

const (
	ActionNone = iota
	ActionContinue
	ActionDrop
	ActionSynth
)

const (
	ReturnCodePass = iota
	ReturnCodeSynth
)

type ReturnCode int

var ReturnCodeToString = map[ReturnCode]string{
	ReturnCodePass:  "PASS",
	ReturnCodeSynth: "SYNTH",
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
	undelegatedSet *critbitgo.Trie
	bravedns       dnsx.BraveDNS
	state          *InterceptState
}

type InterceptState struct {
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
func (ic *Intercept) HandleRequest(packet []byte, needsEDNS0Padding bool) ([]byte, error) {
	msg := dns.Msg{}
	state := ic.state
	if err := msg.Unpack(packet); err != nil {
		return packet, err
	}
	if len(msg.Question) != 1 {
		return packet, errors.New("Unexpected number of questions")
	}
	qName, err := xdns.NormalizeQName(msg.Question[0].Name)
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
	if err := ic.requestBlockedByBraveDNS(packet); err != nil {
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
		if paddedPacket2, _ := xdns.AddEDNS0PaddingIfNoneFound(&msg, packet2, padLen); paddedPacket2 != nil {
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
		// HasTCFlag is always false because currently transport is TCP only
		if len(packet) >= xdns.MinDNSPacketSize && xdns.HasTCFlag(packet) {
			log.Warnf("has-tc-flag, retry with tcp, ignore err: %w", err)
			err = nil
		}
		log.Errorf("has-tc-flag not set, intercept-handle-response err: %w", err)
		return packet, err
	}

	xdns.RemoveEDNS0Options(&msg)

	ic.responseBlockedByBraveDNS(packet)

	if state.action == ActionSynth && len(state.blocklists) > 0 {
		log.Debugf("bravedns locally blocked response", state.blocklists)
		return packet, nil
	}

	packet2, err := msg.PackBuffer(packet)
	if err != nil {
		log.Errorf("intercept-handle-response err for pack-buffer: %w", err)
		return packet, err
	}

	if truncate && len(packet2) > state.maxUnencryptedUDPSafePayloadSize {
		return xdns.TruncatedResponse(packet2)
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
	synth := xdns.EmptyResponseFromMessage(msg)
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
	revQname := xdns.StringReverse(state.qName)
	match, _, found := undelegatedSet.LongestPrefix([]byte(revQname))
	if !found {
		return nil
	}
	if len(match) == len(revQname) || revQname[len(match)] == '.' {
		synth := xdns.EmptyResponseFromMessage(msg)
		synth.Rcode = dns.RcodeNameError
		state.response = synth
		state.action = ActionSynth
		state.returnCode = ReturnCodeSynth
	}
	return nil
}

// requestBlockedByBraveDNS blocks DNS names blocked by local rules.
func (ic *Intercept) requestBlockedByBraveDNS(q []byte) error {
	state := ic.state
	b := ic.bravedns

	if b == nil || state.action != ActionContinue || !b.OnDeviceBlock() {
		return nil // nothing to do.
	}

	blocklists, err := b.BlockRequest(q)
	if err != nil {
		log.Debugf("request not blocked %v", err)
		return nil // ignore error
	}
	if len(blocklists) <= 0 {
		log.Debugf("query not blocked blocklist empty")
		return nil // nothing to do
	}

	ans, err := xdns.BlockResponseFromMessage(q)
	if err != nil {
		return err // ignore this error? doh.Transport does.
	}

	state.response = ans
	state.blocklists = blocklists
	state.action = ActionSynth
	state.returnCode = ReturnCodeSynth

	return nil
}

// responseBlockedByBraveDNS blocks DNS names blocked by local rules.
func (ic *Intercept) responseBlockedByBraveDNS(ans []byte) error {
	state := ic.state
	b := ic.bravedns

	if b == nil || !b.OnDeviceBlock() {
		return nil // nothing to do.
	}

	blocklists, err := b.BlockResponse(ans)
	if err != nil {
		log.Debugf("response not blocked %v", err)
		return nil // ignore error
	}
	if len(blocklists) <= 0 {
		log.Debugf("query not blocked blocklist empty")
		return nil // nothing to do
	}

	res, err := xdns.RefusedResponseFromMessage(state.question)
	if err != nil {
		log.Warnf("could not pack blocked dns ans %v", err)
		return err // ignore this error? doh.Transport does.
	}

	state.response = res
	state.blocklists = blocklists
	state.action = ActionSynth
	state.returnCode = ReturnCodeSynth

	return nil
}

func NewIntercept(set *critbitgo.Trie, bravedns dnsx.BraveDNS) *Intercept {
	return &Intercept{
		undelegatedSet: set,
		bravedns:       bravedns,
		state:          NewInterceptState(),
	}
}

func NewInterceptState() *InterceptState {
	return &InterceptState{
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
