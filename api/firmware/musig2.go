// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"slices"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
)

const (
	// muSig2SessionIDSize is the size of the device-generated handle of a
	// MuSig2 signing session.
	muSig2SessionIDSize = 32

	// muSig2PubNonceSize is the size of a serialized BIP-327 public nonce.
	muSig2PubNonceSize = 66

	// muSig2PartialSigSize is the size of a serialized BIP-327 partial
	// signature.
	muSig2PartialSigSize = 32
)

// btcMuSig2MinVersion is the first firmware version that signs MuSig2 inputs.
var btcMuSig2MinVersion = semver.NewSemVer(9, 29, 0)

// SupportsBTCMuSig2 returns true if the device can contribute to BIP-327 MuSig2
// signing sessions of Taproot wallet policies containing musig() keys.
func (device *Device) SupportsBTCMuSig2() bool {
	return device.version.AtLeast(btcMuSig2MinVersion)
}

// BTCMuSig2Context identifies one MuSig2 context of a transaction: the context
// at Position in the BTCMuSig2Input contexts of the input at InputIndex.
type BTCMuSig2Context struct {
	InputIndex uint32
	Position   uint32
}

// BTCMuSig2Options selects what a BTCSign call contributes to the MuSig2 inputs
// of a transaction. A MuSig2 input is an input whose request carries
// BTCMuSig2Input contexts, one for every aggregate of ours the input can be
// spent with.
//
// There are two ways to sign with the device:
//   - Two rounds: a NONCE call returns the device's public nonces, which are
//     shared with the other participants, and a SIGN call with the identical
//     transaction and everyone's nonces returns the partial signatures. The
//     device keeps the secret nonces in volatile memory in between, so both
//     calls must use the same device connection.
//   - A single NONCE_AND_SIGN call, if every other participant already
//     published its nonce. It returns the device's public nonce and partial
//     signature and keeps no state.
type BTCMuSig2Options struct {
	// Phase is the MuSig2 phase of the call. ABORT is not valid here, use
	// BTCMuSig2Abort instead.
	Phase messages.BTCMuSig2Init_Phase

	// SessionID is the session ID returned by the NONCE call. It must be
	// set for SIGN and be empty for NONCE and NONCE_AND_SIGN.
	SessionID []byte

	// Nonces are the answers to the device's nonce requests, keyed by
	// context. They must be present for every MuSig2 context in the SIGN and
	// NONCE_AND_SIGN phases: for SIGN, they contain every participant's
	// public nonce, including the device's; for NONCE_AND_SIGN, every
	// participant's except the device's. A context that cannot be
	// completed, e.g. because a participant's nonce is missing, is answered
	// with Skip set instead, and the device contributes nothing to it.
	Nonces map[BTCMuSig2Context]*messages.BTCMuSig2NoncesRequest
}

// validate checks the options against the MuSig2 inputs of the transaction.
func (o *BTCMuSig2Options) validate(tx *BTCTx) error {
	if o.Phase == messages.BTCMuSig2Init_ABORT {
		return errp.New("use BTCMuSig2Abort to abort a MuSig2 session")
	}

	wantSessionIDSize := 0
	if o.Phase == messages.BTCMuSig2Init_SIGN {
		wantSessionIDSize = muSig2SessionIDSize
	}
	if len(o.SessionID) != wantSessionIDSize {
		return errp.Newf("invalid MuSig2 session ID for phase %v",
			o.Phase)
	}

	contexts := muSig2Contexts(tx.Inputs)
	for _, context := range contexts {
		_, haveNonces := o.Nonces[context]
		wantNonces := o.Phase != messages.BTCMuSig2Init_NONCE
		if haveNonces != wantNonces {
			return errp.Newf("invalid MuSig2 nonces for input %d "+
				"context %d in phase %v", context.InputIndex,
				context.Position, o.Phase)
		}
	}
	if len(contexts) == 0 {
		return errp.New("MuSig2 options given, but no MuSig2 inputs")
	}
	if len(o.Nonces) > len(contexts) {
		return errp.New("MuSig2 nonces given for unknown contexts")
	}

	if tx.Bip322Message != nil {
		return errp.New("BIP-322 message signing is not supported " +
			"with MuSig2")
	}
	for _, output := range tx.Outputs {
		if output.SilentPayment != nil {
			return errp.New("silent payments are not supported " +
				"with MuSig2")
		}
	}

	return nil
}

// muSig2Contexts returns every MuSig2 context of the inputs.
func muSig2Contexts(inputs []*BTCTxInput) []BTCMuSig2Context {
	var contexts []BTCMuSig2Context
	for index, input := range inputs {
		for position := range input.Input.Musig2 {
			contexts = append(contexts, BTCMuSig2Context{
				InputIndex: uint32(index),
				Position:   uint32(position),
			})
		}
	}

	return contexts
}

// muSig2Session tracks the device's contributions to the MuSig2 inputs over
// one BTCSign call.
type muSig2Session struct {
	options   *BTCMuSig2Options
	inputs    []*BTCTxInput
	sessionID []byte
	results   map[BTCMuSig2Context]*messages.BTCMuSig2Result
}

// newMuSig2Session returns nil if the transaction is signed without MuSig2.
func newMuSig2Session(tx *BTCTx) (*muSig2Session, error) {
	if tx.MuSig2 == nil {
		for index, input := range tx.Inputs {
			if len(input.Input.Musig2) != 0 {
				return nil, errp.Newf("input %d is a MuSig2 "+
					"input, but no MuSig2 options were "+
					"given", index)
			}
		}

		return nil, nil
	}

	if err := tx.MuSig2.validate(tx); err != nil {
		return nil, err
	}

	return &muSig2Session{
		options: tx.MuSig2,
		inputs:  tx.Inputs,
		results: make(map[BTCMuSig2Context]*messages.BTCMuSig2Result),
	}, nil
}

// init returns the MuSig2 field of the sign init request.
func (s *muSig2Session) init() *messages.BTCMuSig2Init {
	if s == nil {
		return nil
	}

	return &messages.BTCMuSig2Init{
		Phase:     s.options.Phase,
		SessionId: s.options.SessionID,
	}
}

// acknowledge checks the response to the sign init request. Firmware without
// MuSig2 support ignores the unknown MuSig2 field and starts an ordinary
// signing session, so the explicit acknowledgement must be checked before any
// input is sent.
func (s *muSig2Session) acknowledge(next *messages.BTCSignNextResponse) error {
	if s == nil {
		return nil
	}

	sessionID := next.Musig2SessionId
	if len(sessionID) != muSig2SessionIDSize {
		return errp.New("the device did not acknowledge the MuSig2 " +
			"session")
	}
	if s.options.Phase == messages.BTCMuSig2Init_SIGN &&
		!bytes.Equal(sessionID, s.options.SessionID) {

		return errp.New("the device acknowledged a different MuSig2 " +
			"session")
	}
	s.sessionID = sessionID

	return nil
}

// nonceRound returns true if the call only collects nonces, in which case the
// device produces no signatures at all.
func (s *muSig2Session) nonceRound() bool {
	return s != nil && s.options.Phase == messages.BTCMuSig2Init_NONCE
}

// noncesRequest returns the answer to the device's nonce request for the
// context at the given position of the input with the given index.
func (s *muSig2Session) noncesRequest(inputIndex,
	position uint32) (*messages.BTCMuSig2NoncesRequest, error) {

	if s == nil || s.nonceRound() {
		return nil, errp.New("unexpected MuSig2 nonces request")
	}
	request, ok := s.options.Nonces[BTCMuSig2Context{
		InputIndex: inputIndex,
		Position:   position,
	}]
	if !ok {
		return nil, errp.Newf("unexpected MuSig2 nonces request for "+
			"input %d context %d", inputIndex, position)
	}

	return request, nil
}

// skipped returns true if the device is asked to contribute nothing to the
// context.
func (s *muSig2Session) skipped(context BTCMuSig2Context) bool {
	request, ok := s.options.Nonces[context]
	return ok && request.Skip
}

// collect checks and records the MuSig2 contributions a response carries, if
// any. A contribution can arrive on any response, identified by its own input
// index and context rather than by the index of the next request.
func (s *muSig2Session) collect(next *messages.BTCSignNextResponse) error {
	if len(next.Musig2Results) != 0 && s == nil {
		return errp.New("unexpected MuSig2 contribution")
	}
	for _, result := range next.Musig2Results {
		if err := s.collectResult(result); err != nil {
			return err
		}
	}

	return nil
}

// collectResult checks and records one MuSig2 contribution.
func (s *muSig2Session) collectResult(result *messages.BTCMuSig2Result) error {
	index := result.InputIndex
	if int(index) >= len(s.inputs) {
		return errp.Newf("MuSig2 contribution for input %d, which is "+
			"not a MuSig2 input", index)
	}

	// The context is identified by its key data.
	var (
		context  BTCMuSig2Context
		metadata *messages.BTCMuSig2Input
	)
	for position, candidate := range s.inputs[index].Input.Musig2 {
		sameLeaf := (result.TapleafHash == nil) ==
			(candidate.TapleafHash == nil) &&
			bytes.Equal(result.TapleafHash, candidate.TapleafHash)
		if !bytes.Equal(result.ContextKey, candidate.ContextKey) ||
			!sameLeaf {

			continue
		}
		if metadata != nil {
			return errp.Newf("ambiguous MuSig2 contribution for "+
				"input %d", index)
		}
		context = BTCMuSig2Context{
			InputIndex: index,
			Position:   uint32(position),
		}
		metadata = candidate
	}
	if metadata == nil {
		return errp.Newf("MuSig2 contribution for input %d does not "+
			"match any of its contexts", index)
	}
	if s.skipped(context) {
		return errp.Newf("MuSig2 contribution for skipped context %d "+
			"of input %d", context.Position, index)
	}
	if _, ok := s.results[context]; ok {
		return errp.Newf("duplicate MuSig2 contribution for input %d "+
			"context %d", index, context.Position)
	}

	isParticipant := slices.ContainsFunc(
		metadata.ParticipantPubkeys, func(key []byte) bool {
			return bytes.Equal(key, result.ParticipantPubkey)
		},
	)
	if !isParticipant {
		return errp.Newf("MuSig2 contribution for input %d does not "+
			"match its context", index)
	}

	nonceSize, sigSize := muSig2PubNonceSize, muSig2PartialSigSize
	switch s.options.Phase {
	case messages.BTCMuSig2Init_NONCE:
		sigSize = 0
	case messages.BTCMuSig2Init_SIGN:
		nonceSize = 0
	}
	if len(result.PublicNonce) != nonceSize ||
		len(result.PartialSignature) != sigSize {

		return errp.Newf("MuSig2 contribution for input %d does not "+
			"match phase %v", index, s.options.Phase)
	}

	s.results[context] = result

	return nil
}

// done checks that the device contributed to every MuSig2 context it was not
// asked to skip, and closed the session it acknowledged.
func (s *muSig2Session) done(next *messages.BTCSignNextResponse) error {
	if s == nil {
		return nil
	}

	if !bytes.Equal(next.Musig2SessionId, s.sessionID) {
		return errp.New("the device closed a different MuSig2 session")
	}
	for _, context := range muSig2Contexts(s.inputs) {
		if s.skipped(context) {
			continue
		}
		if _, ok := s.results[context]; !ok {
			return errp.Newf("missing MuSig2 contribution for "+
				"input %d context %d", context.InputIndex,
				context.Position)
		}
	}

	return nil
}

// BTCMuSig2Abort abandons the pending MuSig2 nonce round with the given session
// ID, destroying the device's secret nonces. The device clears its pending
// round even if the session ID does not match, but reports an error in that
// case.
func (device *Device) BTCMuSig2Abort(sessionID []byte) error {
	if !device.SupportsBTCMuSig2() {
		return UnsupportedError(btcMuSig2MinVersion.String())
	}

	response, err := device.query(&messages.Request{
		Request: &messages.Request_BtcSignInit{
			BtcSignInit: &messages.BTCSignInitRequest{
				Musig2: &messages.BTCMuSig2Init{
					Phase:     messages.BTCMuSig2Init_ABORT,
					SessionId: sessionID,
				},
			},
		},
	})
	if err != nil {
		return err
	}
	next, ok := response.Response.(*messages.Response_BtcSignNext)
	if !ok || next.BtcSignNext.Type != messages.BTCSignNextResponse_DONE {
		return errp.New("unexpected response")
	}

	return nil
}
