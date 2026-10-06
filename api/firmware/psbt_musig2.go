// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strconv"
	"strings"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/errp"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/psbt/v2"
)

// PSBTMuSig2Options selects what BTCSignPSBT contributes to the MuSig2 inputs of
// a PSBT. BTCPSBTMuSig2Step returns the phase that fits the state of a PSBT.
type PSBTMuSig2Options struct {
	// Phase is the MuSig2 phase of the call. ABORT is not valid here.
	Phase messages.BTCMuSig2Init_Phase

	// SessionID must be the session ID of the preceding NONCE call for
	// SIGN, and empty otherwise. After a successful call, it holds the
	// session ID the device assigned to the call.
	SessionID []byte
}

// PSBTMuSig2Step is what a participant has to do next for the MuSig2 inputs of
// a PSBT.
type PSBTMuSig2Step int

const (
	// PSBTMuSig2StepNone means the PSBT has no MuSig2 input with our key.
	PSBTMuSig2StepNone PSBTMuSig2Step = iota

	// PSBTMuSig2StepNonce means we have to contribute our nonces to every
	// spend path of ours, and no other participant published every nonce
	// of one yet: sign with the NONCE phase and keep the session ID for the
	// SIGN phase.
	PSBTMuSig2StepNonce

	// PSBTMuSig2StepWait means our nonces are present, but no spend path
	// we contributed to has every other participant's nonce yet.
	PSBTMuSig2StepWait

	// PSBTMuSig2StepSign means every participant's nonce, including ours,
	// is present for a spend path: sign with the SIGN phase. The spend
	// paths that are not complete are skipped.
	PSBTMuSig2StepSign

	// PSBTMuSig2StepNonceAndSign means we did not contribute yet, and every
	// other participant published its nonce for a spend path: sign with
	// the NONCE_AND_SIGN phase. The other spend paths are skipped.
	PSBTMuSig2StepNonceAndSign

	// PSBTMuSig2StepDone means our partial signatures are present.
	PSBTMuSig2StepDone
)

// Phase returns the phase to sign with for the steps that require signing.
func (s PSBTMuSig2Step) Phase() (messages.BTCMuSig2Init_Phase, bool) {
	switch s {
	case PSBTMuSig2StepNonce:
		return messages.BTCMuSig2Init_NONCE, true
	case PSBTMuSig2StepSign:
		return messages.BTCMuSig2Init_SIGN, true
	case PSBTMuSig2StepNonceAndSign:
		return messages.BTCMuSig2Init_NONCE_AND_SIGN, true
	default:
		return 0, false
	}
}

// muSig2Key is our participant key in the MuSig2 aggregates of a PSBT input or
// output.
type muSig2Key struct {
	// participant is our participant key's derivation, pointing to the
	// participant's origin. MuSig2 participant keys are not derived
	// further before aggregation.
	participant *psbt.TaprootBip32Derivation

	// pubKey is our compressed participant key.
	pubKey *btcec.PublicKey

	// records are the participants records our key is part of.
	records []*psbt.MuSig2Participants

	// keypath is the address selector the device expects: our origin
	// followed by the branch and index the aggregate is derived at.
	keypath []uint32

	// infos are the signing contexts of a MuSig2 input, one for every
	// aggregate of ours the input can be spent with, in the order the
	// device gets them. Nil for outputs.
	infos []*psbt.MuSig2SigningInfo
}

// fingerprintUint32 converts a 4 byte fingerprint to the representation of
// psbt.TaprootBip32Derivation.
func fingerprintUint32(fingerprint []byte) uint32 {
	return binary.LittleEndian.Uint32(fingerprint)
}

// findOurMuSig2Participant returns our participant key if it is part of one of
// the given participants records, or nil otherwise.
func findOurMuSig2Participant(ourRootFingerprint uint32,
	records []*psbt.MuSig2Participants,
	derivations []*psbt.TaprootBip32Derivation) *muSig2Key {

	for _, derivation := range derivations {
		if derivation.MasterKeyFingerprint != ourRootFingerprint {
			continue
		}

		var key *muSig2Key
		for _, record := range records {
			for _, participant := range record.Keys {
				xOnly := schnorr.SerializePubKey(participant)
				if !bytes.Equal(xOnly, derivation.XOnlyPubKey) {
					continue
				}
				if key == nil {
					key = &muSig2Key{
						participant: derivation,
						pubKey:      participant,
					}
				}
				key.records = append(key.records, record)
			}
		}
		if key != nil {
			return key
		}
	}

	return nil
}

// completeMuSig2Input determines the signing contexts of our key in the MuSig2
// input and the keypath the device expects for it.
func completeMuSig2Input(packet *psbt.Packet, inputIndex int,
	key *muSig2Key) error {

	infos, err := psbt.MuSig2SigningInfos(packet, inputIndex, key.pubKey)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		return errp.Newf("our key is part of no MuSig2 spend path of "+
			"input %d", inputIndex)
	}

	// All aggregates of an input are derived at the same branch and index:
	// the address the input spends.
	for _, info := range infos[1:] {
		if !slices.Equal(info.DerivationPath, infos[0].DerivationPath) {
			return errp.Newf("the MuSig2 spend paths of input %d "+
				"are derived differently", inputIndex)
		}
	}
	key.infos = infos
	key.keypath = slices.Concat(
		key.participant.Bip32Path, infos[0].DerivationPath,
	)

	return nil
}

// completeMuSig2Output determines the keypath the device expects for our
// MuSig2 change output. The descriptor wallet records the aggregate's
// derivation from the BIP-328 synthetic root, whose fingerprint is the
// hash160 of the aggregate key.
func completeMuSig2Output(output *psbt.POutput, key *muSig2Key) error {
	var path []uint32
	for _, record := range key.records {
		fingerprint := fingerprintUint32(
			address.Hash160(record.AggregateKey.SerializeCompressed())[:4],
		)
		for _, derivation := range output.TaprootBip32Derivation {
			if derivation.MasterKeyFingerprint != fingerprint {
				continue
			}
			if path != nil && !slices.Equal(path, derivation.Bip32Path) {
				return errp.New("MuSig2 aggregates of the output " +
					"are derived at different paths")
			}
			path = derivation.Bip32Path
		}
	}
	if path == nil {
		return errp.New("no derivation of the MuSig2 aggregate found " +
			"in output")
	}
	key.keypath = slices.Concat(key.participant.Bip32Path, path)

	return nil
}

// muSig2KeyExpression returns the key expression of the registered policy that
// aggregates exactly the given participant keys, e.g. musig(@0,@1)/**.
func muSig2KeyExpression(policy *messages.BTCScriptConfig_Policy,
	participants []*btcec.PublicKey) (string, error) {

	var want []int
	for _, participant := range participants {
		index := slices.IndexFunc(policy.Keys,
			func(key *messages.KeyOriginInfo) bool {
				return bytes.Equal(
					key.GetXpub().GetPublicKey(),
					participant.SerializeCompressed(),
				)
			},
		)
		if index < 0 {
			return "", errp.Newf("MuSig2 participant %x is not a "+
				"key of the policy",
				participant.SerializeCompressed())
		}
		want = append(want, index)
	}
	slices.Sort(want)

	var found []string
	const prefix = "musig("
	for rest := policy.Policy; ; {
		start := strings.Index(rest, prefix)
		if start < 0 {
			break
		}
		rest = rest[start:]
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return "", errp.New("unterminated musig() expression")
		}

		var indices []int
		for _, placeholder := range strings.Split(
			rest[len(prefix):end], ",",
		) {

			index, err := strconv.Atoi(
				strings.TrimPrefix(placeholder, "@"),
			)
			if err != nil || !strings.HasPrefix(placeholder, "@") {
				return "", errp.Newf("invalid musig() "+
					"participant %q", placeholder)
			}
			indices = append(indices, index)
		}
		slices.Sort(indices)

		derivation := rest[end+1:]
		switch {
		case strings.HasPrefix(derivation, "/**"):
			derivation = "/**"
		case strings.HasPrefix(derivation, "/<"):
			closing := strings.Index(derivation, ">/*")
			if closing < 0 {
				return "", errp.New("invalid musig() derivation")
			}
			derivation = derivation[:closing+len(">/*")]
		default:
			return "", errp.New("invalid musig() derivation")
		}

		if slices.Equal(indices, want) {
			found = append(found, rest[:end+1]+derivation)
		}
		rest = rest[end+1:]
	}
	if len(found) != 1 {
		return "", errp.Newf("expected one musig() expression for the "+
			"MuSig2 participants in the policy, found %d",
			len(found))
	}

	return found[0], nil
}

// btcMuSig2Inputs returns the BIP-373 contexts the device needs for our key in
// a MuSig2 input.
func (key *muSig2Key) btcMuSig2Inputs(
	policy *messages.BTCScriptConfig_Policy) ([]*messages.BTCMuSig2Input, error) {

	inputs := make([]*messages.BTCMuSig2Input, 0, len(key.infos))
	for _, info := range key.infos {
		record := info.Participants
		expression, err := muSig2KeyExpression(policy, record.Keys)
		if err != nil {
			return nil, err
		}

		participants := make([][]byte, len(record.Keys))
		for index, participant := range record.Keys {
			participants[index] = participant.SerializeCompressed()
		}

		inputs = append(inputs, &messages.BTCMuSig2Input{
			KeyExpression:      expression,
			AggregateKey:       record.AggregateKey.SerializeCompressed(),
			ParticipantPubkeys: participants,
			ContextKey:         info.ContextKey.SerializeCompressed(),
			TapleafHash:        info.TapLeafHash,
		})
	}

	return inputs, nil
}

// sameMuSig2Context returns true if the given key data belongs to the signing
// context.
func sameMuSig2Context(info *psbt.MuSig2SigningInfo,
	aggregateKey *btcec.PublicKey, tapLeafHash []byte) bool {

	return aggregateKey.IsEqual(info.ContextKey) &&
		bytes.Equal(tapLeafHash, info.TapLeafHash)
}

// pubNonces returns the public nonces of the signing context, keyed by the
// compressed participant key.
func pubNonces(info *psbt.MuSig2SigningInfo,
	input *psbt.PInput) map[string]*psbt.MuSig2PubNonce {

	nonces := make(map[string]*psbt.MuSig2PubNonce)
	for _, nonce := range input.MuSig2PubNonces {
		if sameMuSig2Context(info, nonce.AggregateKey, nonce.TapLeafHash) {
			nonces[string(nonce.PubKey.SerializeCompressed())] = nonce
		}
	}

	return nonces
}

// muSig2ContextState is how far a signing context of our key is.
type muSig2ContextState struct {
	// ourNonce is true if our public nonce is present.
	ourNonce bool

	// othersComplete is true if every other participant's nonce is
	// present.
	othersComplete bool

	// signed is true if our partial signature is present.
	signed bool
}

// state returns how far the signing context of our key is in the input.
func (key *muSig2Key) state(info *psbt.MuSig2SigningInfo,
	input *psbt.PInput) muSig2ContextState {

	var state muSig2ContextState
	for _, partialSig := range input.MuSig2PartialSigs {
		if partialSig.PubKey.IsEqual(key.pubKey) &&
			sameMuSig2Context(
				info, partialSig.AggregateKey,
				partialSig.TapLeafHash,
			) {

			state.signed = true
		}
	}

	nonces := pubNonces(info, input)
	_, state.ourNonce = nonces[string(key.pubKey.SerializeCompressed())]
	state.othersComplete = true
	for _, participant := range info.Participants.Keys {
		if participant.IsEqual(key.pubKey) {
			continue
		}
		if _, ok := nonces[string(participant.SerializeCompressed())]; !ok {
			state.othersComplete = false
		}
	}

	return state
}

// signable returns true if the device can contribute its partial signature to
// a context in the given phase.
func (state muSig2ContextState) signable(
	phase messages.BTCMuSig2Init_Phase) bool {

	switch phase {
	case messages.BTCMuSig2Init_SIGN:
		return state.ourNonce && state.othersComplete && !state.signed

	case messages.BTCMuSig2Init_NONCE_AND_SIGN:
		return !state.ourNonce && state.othersComplete

	default:
		return false
	}
}

// muSig2Step returns what we have to do next for the given contexts of our key
// in a PSBT, following one rule for any number of spend paths: contribute
// nonces to every spend path while we did not contribute to any, then sign
// those whose nonces are complete. A spend path one of whose participants
// never takes part is left alone, so the signers need not agree on the spend
// path in advance.
func muSig2Step(states []muSig2ContextState) PSBTMuSig2Step {
	if len(states) == 0 {
		return PSBTMuSig2StepNone
	}

	contributed := slices.ContainsFunc(
		states, func(state muSig2ContextState) bool {
			return state.ourNonce || state.signed
		},
	)
	if !contributed {
		if slices.ContainsFunc(
			states, func(state muSig2ContextState) bool {
				return state.signable(
					messages.BTCMuSig2Init_NONCE_AND_SIGN,
				)
			},
		) {

			return PSBTMuSig2StepNonceAndSign
		}

		return PSBTMuSig2StepNonce
	}

	if slices.ContainsFunc(states, func(state muSig2ContextState) bool {
		return state.signable(messages.BTCMuSig2Init_SIGN)
	}) {

		return PSBTMuSig2StepSign
	}
	if slices.ContainsFunc(states, func(state muSig2ContextState) bool {
		return state.ourNonce && !state.signed
	}) {

		return PSBTMuSig2StepWait
	}

	return PSBTMuSig2StepDone
}

// noncesRequest returns the answer to the device's nonces request for a
// context of the input in the given phase: every participant's nonce for SIGN,
// every participant's but ours for NONCE_AND_SIGN, and a skip if the context
// cannot be completed in this phase.
func (key *muSig2Key) noncesRequest(inputIndex int,
	info *psbt.MuSig2SigningInfo, input *psbt.PInput,
	phase messages.BTCMuSig2Init_Phase) (*messages.BTCMuSig2NoncesRequest,
	error) {

	request := &messages.BTCMuSig2NoncesRequest{
		InputIndex:  uint32(inputIndex),
		ContextKey:  info.ContextKey.SerializeCompressed(),
		TapleafHash: info.TapLeafHash,
	}
	if !key.state(info, input).signable(phase) {
		request.Skip = true
		return request, nil
	}

	nonces := pubNonces(info, input)
	for _, participant := range info.Participants.Keys {
		ours := participant.IsEqual(key.pubKey)
		if ours && phase == messages.BTCMuSig2Init_NONCE_AND_SIGN {
			continue
		}

		serialized := participant.SerializeCompressed()
		nonce, ok := nonces[string(serialized)]
		if !ok {
			return nil, errp.Newf("missing MuSig2 nonce of "+
				"participant %x in input %d", serialized,
				inputIndex)
		}
		request.Nonces = append(request.Nonces, &messages.BTCMuSig2Nonce{
			ParticipantPubkey: serialized,
			PublicNonce:       nonce.PubNonce[:],
		})
	}

	return request, nil
}

// addContribution records the device's contribution to a signing context in
// the input, replacing a previous contribution of our key to the same context.
func (key *muSig2Key) addContribution(input *psbt.PInput,
	info *psbt.MuSig2SigningInfo, result *messages.BTCMuSig2Result) error {

	if len(result.PublicNonce) != 0 {
		nonce := &psbt.MuSig2PubNonce{
			PubKey:       key.pubKey,
			AggregateKey: info.ContextKey,
			TapLeafHash:  info.TapLeafHash,
		}
		copy(nonce.PubNonce[:], result.PublicNonce)
		if err := nonce.Validate(); err != nil {
			return err
		}

		input.MuSig2PubNonces = slices.DeleteFunc(
			input.MuSig2PubNonces,
			func(existing *psbt.MuSig2PubNonce) bool {
				return bytes.Equal(
					existing.KeyData(), nonce.KeyData(),
				)
			},
		)
		input.MuSig2PubNonces = append(input.MuSig2PubNonces, nonce)
	}

	if len(result.PartialSignature) != 0 {
		var partialSig musig2.PartialSignature
		err := partialSig.Decode(bytes.NewReader(result.PartialSignature))
		if err != nil {
			return err
		}
		sig := &psbt.MuSig2PartialSig{
			PubKey:       key.pubKey,
			AggregateKey: info.ContextKey,
			TapLeafHash:  info.TapLeafHash,
			PartialSig:   partialSig,
		}

		input.MuSig2PartialSigs = slices.DeleteFunc(
			input.MuSig2PartialSigs,
			func(existing *psbt.MuSig2PartialSig) bool {
				return bytes.Equal(existing.KeyData(), sig.KeyData())
			},
		)
		input.MuSig2PartialSigs = append(input.MuSig2PartialSigs, sig)
	}

	return nil
}

// BTCPSBTMuSig2Step returns what the signer with the given root fingerprint has
// to do next for the MuSig2 inputs of the PSBT. All MuSig2 inputs are signed in
// one call, considering every spend path of ours of every input.
func BTCPSBTMuSig2Step(packet *psbt.Packet,
	ourRootFingerprint []byte) (PSBTMuSig2Step, error) {

	var states []muSig2ContextState
	for inputIndex := range packet.Inputs {
		input := &packet.Inputs[inputIndex]
		key := findOurMuSig2Participant(
			fingerprintUint32(ourRootFingerprint),
			input.MuSig2Participants, input.TaprootBip32Derivation,
		)
		if key == nil {
			continue
		}
		if err := completeMuSig2Input(packet, inputIndex, key); err != nil {
			return 0, err
		}

		for _, info := range key.infos {
			states = append(states, key.state(info, input))
		}
	}

	return muSig2Step(states), nil
}

// addMuSig2Options selects the MuSig2 phase of the transaction and answers the
// device's nonces requests from the PSBT.
func (r *psbtConvertResult) addMuSig2Options(packet *psbt.Packet,
	options *PSBTMuSig2Options) error {

	if !slices.ContainsFunc(r.ourKeys, func(key *ourKey) bool {
		return key.muSig2 != nil
	}) {

		if options != nil {
			return errp.New("MuSig2 options given, but the PSBT has " +
				"no MuSig2 inputs with our key")
		}
		return nil
	}
	if options == nil {
		return errp.New("the PSBT has MuSig2 inputs with our key, but " +
			"no MuSig2 options were given")
	}

	r.tx.MuSig2 = &BTCMuSig2Options{
		Phase:     options.Phase,
		SessionID: options.SessionID,
	}
	if options.Phase == messages.BTCMuSig2Init_NONCE {
		return nil
	}

	r.tx.MuSig2.Nonces = make(
		map[BTCMuSig2Context]*messages.BTCMuSig2NoncesRequest,
	)
	for inputIndex, key := range r.ourKeys {
		if key.muSig2 == nil {
			continue
		}
		for position, info := range key.muSig2.infos {
			request, err := key.muSig2.noncesRequest(
				inputIndex, info, &packet.Inputs[inputIndex],
				options.Phase,
			)
			if err != nil {
				return err
			}
			r.tx.MuSig2.Nonces[BTCMuSig2Context{
				InputIndex: uint32(inputIndex),
				Position:   uint32(position),
			}] = request
		}
	}

	return nil
}
