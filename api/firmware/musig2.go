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
var btcMuSig2MinVersion = semver.NewSemVer(9, 28, 0)

// SupportsBTCMuSig2 returns true if the device can contribute to BIP-327 MuSig2
// signing sessions of Taproot wallet policies containing musig() keys.
func (device *Device) SupportsBTCMuSig2() bool {
	return device.version.AtLeast(btcMuSig2MinVersion)
}

// BTCMuSig2Options selects what a BTCSign call contributes to the MuSig2 inputs
// of a transaction. A MuSig2 input is an input whose request carries a
// BTCMuSig2Input context.
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

	// Nonces are the answers to the device's nonce requests, keyed by input
	// index. They must be present for every MuSig2 input in the SIGN and
	// NONCE_AND_SIGN phases: for SIGN, they contain every participant's
	// public nonce, including the device's; for NONCE_AND_SIGN, every
	// participant's except the device's.
	Nonces map[uint32]*messages.BTCMuSig2NoncesRequest
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

	numMuSig2Inputs := 0
	for index, input := range tx.Inputs {
		if input.Input.Musig2 == nil {
			continue
		}
		numMuSig2Inputs++

		_, haveNonces := o.Nonces[uint32(index)]
		wantNonces := o.Phase != messages.BTCMuSig2Init_NONCE
		if haveNonces != wantNonces {
			return errp.Newf("invalid MuSig2 nonces for input %d "+
				"in phase %v", index, o.Phase)
		}
	}
	if numMuSig2Inputs == 0 {
		return errp.New("MuSig2 options given, but no MuSig2 inputs")
	}
	if len(o.Nonces) > numMuSig2Inputs {
		return errp.New("MuSig2 nonces given for non-MuSig2 inputs")
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

// muSig2Session tracks the device's contributions to the MuSig2 inputs over
// one BTCSign call.
type muSig2Session struct {
	options   *BTCMuSig2Options
	inputs    []*BTCTxInput
	sessionID []byte
	results   map[uint32]*messages.BTCMuSig2Result
}

// newMuSig2Session returns nil if the transaction is signed without MuSig2.
func newMuSig2Session(tx *BTCTx) (*muSig2Session, error) {
	if tx.MuSig2 == nil {
		for index, input := range tx.Inputs {
			if input.Input.Musig2 != nil {
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
		results: make(map[uint32]*messages.BTCMuSig2Result),
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

// noncesRequest returns the answer to the device's nonce request for the input
// with the given index.
func (s *muSig2Session) noncesRequest(
	inputIndex uint32) (*messages.BTCMuSig2NoncesRequest, error) {

	if s == nil || s.nonceRound() {
		return nil, errp.New("unexpected MuSig2 nonces request")
	}
	request, ok := s.options.Nonces[inputIndex]
	if !ok {
		return nil, errp.Newf("unexpected MuSig2 nonces request for "+
			"input %d", inputIndex)
	}

	return request, nil
}

// collect checks and records the MuSig2 contribution a response carries, if
// any. A contribution can arrive on any response, identified by its own input
// index rather than by the index of the next request.
func (s *muSig2Session) collect(next *messages.BTCSignNextResponse) error {
	result := next.Musig2Result
	if result == nil {
		return nil
	}
	if s == nil {
		return errp.New("unexpected MuSig2 contribution")
	}

	index := result.InputIndex
	if int(index) >= len(s.inputs) || s.inputs[index].Input.Musig2 == nil {
		return errp.Newf("MuSig2 contribution for input %d, which is "+
			"not a MuSig2 input", index)
	}
	if _, ok := s.results[index]; ok {
		return errp.Newf("duplicate MuSig2 contribution for input %d",
			index)
	}

	context := s.inputs[index].Input.Musig2
	sameLeaf := (result.TapleafHash == nil) == (context.TapleafHash == nil) &&
		bytes.Equal(result.TapleafHash, context.TapleafHash)
	isParticipant := slices.ContainsFunc(
		context.ParticipantPubkeys, func(key []byte) bool {
			return bytes.Equal(key, result.ParticipantPubkey)
		},
	)
	if !bytes.Equal(result.ContextKey, context.ContextKey) || !sameLeaf ||
		!isParticipant {

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

	s.results[index] = result

	return nil
}

// done checks that the device contributed to every MuSig2 input and closed the
// session it acknowledged.
func (s *muSig2Session) done(next *messages.BTCSignNextResponse) error {
	if s == nil {
		return nil
	}

	if !bytes.Equal(next.Musig2SessionId, s.sessionID) {
		return errp.New("the device closed a different MuSig2 session")
	}
	for index, input := range s.inputs {
		if input.Input.Musig2 == nil {
			continue
		}
		if _, ok := s.results[uint32(index)]; !ok {
			return errp.Newf("missing MuSig2 contribution for "+
				"input %d", index)
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
