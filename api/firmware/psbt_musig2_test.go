// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"slices"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
)

// newTestMuSig2Wallet returns a tr(musig(@0,@1)/**) wallet of two software
// participants, the first playing the device.
func newTestMuSig2Wallet(t *testing.T) *muSig2Wallet {
	t.Helper()

	var wallet muSig2Wallet
	wallet.device, _ = newSoftwareParticipant(t, "device")
	wallet.software, wallet.softwareKey = newSoftwareParticipant(t, "software")
	wallet.complete(t)

	return &wallet
}

func TestMuSig2KeyExpression(t *testing.T) {
	keys := make([]*btcec.PublicKey, 3)
	policy := &messages.BTCScriptConfig_Policy{}
	for index := range keys {
		participant, _ := newSoftwareParticipant(t, string(rune('a'+index)))
		keys[index] = participant.pubKey
		xpub, err := NewXPub(participant.xpub.String())
		require.NoError(t, err)
		policy.Keys = append(policy.Keys, &messages.KeyOriginInfo{Xpub: xpub})
	}

	tests := []struct {
		policy       string
		participants []*btcec.PublicKey
		expression   string
		errMsg       string
	}{{
		policy:       "tr(musig(@0,@1)/**)",
		participants: []*btcec.PublicKey{keys[1], keys[0]},
		expression:   "musig(@0,@1)/**",
	}, {
		policy:       "tr(musig(@1,@0)/<2;3>/*)",
		participants: []*btcec.PublicKey{keys[0], keys[1]},
		expression:   "musig(@1,@0)/<2;3>/*",
	}, {
		policy: "tr(musig(@0,@1)/**,{pk(musig(@0,@2)/**)," +
			"pk(musig(@1,@2)/**)})",
		participants: []*btcec.PublicKey{keys[2], keys[0]},
		expression:   "musig(@0,@2)/**",
	}, {
		policy:       "tr(musig(@0,@1)/**)",
		participants: []*btcec.PublicKey{keys[0], keys[2]},
		errMsg:       "found 0",
	}, {
		policy: "tr(musig(@0,@1)/**)",
		participants: []*btcec.PublicKey{
			keys[0], wallet(t).sorted[0],
		},
		errMsg: "not a key of the policy",
	}, {
		policy:       "tr(musig(@0,x)/**)",
		participants: []*btcec.PublicKey{keys[0], keys[1]},
		errMsg:       "invalid musig() participant",
	}, {
		policy:       "tr(musig(@0,@1)/0/*)",
		participants: []*btcec.PublicKey{keys[0], keys[1]},
		errMsg:       "invalid musig() derivation",
	}}
	for _, test := range tests {
		t.Run(test.policy, func(t *testing.T) {
			policy.Policy = test.policy
			expression, err := muSig2KeyExpression(
				policy, test.participants,
			)
			if test.errMsg != "" {
				require.ErrorContains(t, err, test.errMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expression, expression)
		})
	}
}

// wallet is a shorthand for tests that only need unrelated keys.
func wallet(t *testing.T) *muSig2Wallet {
	t.Helper()

	return newTestMuSig2Wallet(t)
}

// TestNewBTCTxFromPSBTMuSig2 asserts that a MuSig2 input and change output are
// mapped to the device's address selector keypath and BIP-373 context.
func TestNewBTCTxFromPSBTMuSig2(t *testing.T) {
	w := newTestMuSig2Wallet(t)
	packet := w.newPSBT(t)
	options := &PSBTSignOptions{ForceScriptConfig: w.scriptConfig}

	result, err := newBTCTxFromPSBT(
		btcMuSig2MinVersion, packet, w.device.fingerprint, options,
	)
	require.NoError(t, err)

	input := result.tx.Inputs[0].Input
	require.Equal(t, slices.Concat(muSig2TestKeypath, []uint32{0, 0}), input.Keypath)
	require.Len(t, input.Musig2, 1)
	context := input.Musig2[0]
	require.Equal(t, "musig(@0,@1)/**", context.KeyExpression)
	require.Equal(t, w.aggregate.SerializeCompressed(), context.AggregateKey)
	require.Equal(t, [][]byte{
		w.sorted[0].SerializeCompressed(), w.sorted[1].SerializeCompressed(),
	}, context.ParticipantPubkeys)
	require.Nil(t, context.TapleafHash)
	info := muSig2SigningInfo(t, packet, w.device.pubKey)
	require.Equal(t, info.ContextKey.SerializeCompressed(), context.ContextKey)

	change := result.tx.Outputs[1]
	require.True(t, change.Ours)
	require.Equal(t, slices.Concat(muSig2TestKeypath, []uint32{1, 7}), change.Keypath)
	require.False(t, result.tx.Outputs[0].Ours)

	// MuSig2 inputs can only be signed with the registered policy.
	_, err = newBTCTxFromPSBT(
		btcMuSig2MinVersion, packet, w.device.fingerprint, nil,
	)
	require.ErrorContains(t, err, "policy script config")

	// Without MuSig2 options, the device would be asked for ordinary
	// signatures.
	require.ErrorContains(
		t, result.addMuSig2Options(packet, nil), "no MuSig2 options",
	)

	// A signer that is not a participant has no MuSig2 inputs.
	step, err := BTCPSBTMuSig2Step(packet, []byte{1, 2, 3, 4})
	require.NoError(t, err)
	require.Equal(t, PSBTMuSig2StepNone, step)
}

// TestBTCPSBTMuSig2Step asserts the signing step for every combination of the
// nonces and partial signatures present in a MuSig2 input.
func TestBTCPSBTMuSig2Step(t *testing.T) {
	w := newTestMuSig2Wallet(t)
	fingerprint := w.device.fingerprint
	_, deviceKey := newSoftwareParticipant(t, "device")

	packet := w.newPSBT(t)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepNonce)

	device := &softwareSigner{key: deviceKey}
	device.nonce(t, packet)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepWait)

	software := &softwareSigner{key: w.softwareKey}
	software.nonce(t, packet)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepSign)

	device.sign(t, packet)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepDone)
	software.sign(t, packet)
	requireValidSpend(t, packet)

	packet = w.newPSBT(t)
	software = &softwareSigner{key: w.softwareKey}
	software.nonce(t, packet)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepNonceAndSign)

	// The nonces request of the single round excludes our nonce, the one
	// of the signing round includes it.
	result, err := newBTCTxFromPSBT(
		btcMuSig2MinVersion, packet, fingerprint,
		&PSBTSignOptions{ForceScriptConfig: w.scriptConfig},
	)
	require.NoError(t, err)
	require.NoError(t, result.addMuSig2Options(packet, &PSBTMuSig2Options{
		Phase: messages.BTCMuSig2Init_NONCE_AND_SIGN,
	}))
	nonces := result.tx.MuSig2.Nonces[BTCMuSig2Context{}]
	require.False(t, nonces.Skip)
	require.Len(t, nonces.Nonces, 1)
	require.Equal(
		t, w.software.pubKey.SerializeCompressed(),
		nonces.Nonces[0].ParticipantPubkey,
	)

	// Without our nonce, there is nothing to sign in a signing round.
	require.NoError(t, result.addMuSig2Options(packet, &PSBTMuSig2Options{
		Phase: messages.BTCMuSig2Init_SIGN,
	}))
	nonces = result.tx.MuSig2.Nonces[BTCMuSig2Context{}]
	require.True(t, nonces.Skip)
	require.Empty(t, nonces.Nonces)

	// An input whose other nonce is missing is skipped in the single
	// round, the others are signed.
	packet.UnsignedTx.AddTxIn(packet.UnsignedTx.TxIn[0])
	fresh := w.newPSBT(t).Inputs[0]
	packet.Inputs = append(packet.Inputs, fresh)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepNonceAndSign)
	result, err = newBTCTxFromPSBT(
		btcMuSig2MinVersion, packet, fingerprint,
		&PSBTSignOptions{ForceScriptConfig: w.scriptConfig},
	)
	require.NoError(t, err)
	require.NoError(t, result.addMuSig2Options(packet, &PSBTMuSig2Options{
		Phase: messages.BTCMuSig2Init_NONCE_AND_SIGN,
	}))
	require.False(t, result.tx.MuSig2.Nonces[BTCMuSig2Context{}].Skip)
	require.True(t, result.tx.MuSig2.Nonces[BTCMuSig2Context{
		InputIndex: 1,
	}].Skip)
}

// newSeveralSpendPathsPSBT returns a PSBT spending an input of the policy
// tr(musig(@0,@1)/**,pk(musig(@0,@2)/**)) of the wallet and the other
// participant, whose device key is part of the key path aggregate and of a
// leaf aggregate. The change output of newPSBT is external here. It returns
// the leaf hash and the policy too.
func newSeveralSpendPathsPSBT(t *testing.T, w *muSig2Wallet,
	other muSig2Participant) (*psbt.Packet, []byte,
	*messages.BTCScriptConfigWithKeypath) {

	t.Helper()

	leafWallet := &muSig2Wallet{device: w.device, software: other}
	leafWallet.complete(t)

	internalKey, derivations, _ := w.derivations(t, 0, 0)
	leafKey, leafDerivations, _ := leafWallet.derivations(t, 0, 0)
	leafScript, err := txscript.NewScriptBuilder().AddData(leafKey).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)
	tapLeaf := txscript.NewBaseTapLeaf(leafScript)
	leafHash := tapLeaf.TapHash()
	tree := txscript.AssembleTaprootScriptTree(tapLeaf)
	rootHash := tree.RootNode.TapHash()
	internalPubKey, err := schnorr.ParsePubKey(internalKey)
	require.NoError(t, err)
	controlBlockStruct := tree.LeafMerkleProofs[0].ToControlBlock(
		internalPubKey,
	)
	controlBlock, err := controlBlockStruct.ToBytes()
	require.NoError(t, err)
	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(internalPubKey, rootHash[:]),
	)
	require.NoError(t, err)

	packet := w.newPSBT(t)
	input := &packet.Inputs[0]
	input.WitnessUtxo.PkScript = pkScript
	input.TaprootMerkleRoot = rootHash[:]
	input.TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBlock,
		Script:       leafScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	leafDerivations[0].LeafHashes = [][]byte{leafHash[:]}
	input.TaprootBip32Derivation = slices.Concat(
		derivations, leafDerivations[:1],
	)
	input.MuSig2Participants = append(
		input.MuSig2Participants, &psbt.MuSig2Participants{
			AggregateKey: leafWallet.aggregate,
			Keys:         leafWallet.sorted,
		},
	)

	packet.Outputs[1] = psbt.POutput{}

	return packet, leafHash[:], leafScriptConfig(t, w, other)
}

// TestBTCPSBTMuSig2StepSeveralSpendPaths asserts that the device contributes to
// every spend path of an input its key is part of: nonces to all of them, and
// partial signatures to those whose nonces are complete, skipping the others.
func TestBTCPSBTMuSig2StepSeveralSpendPaths(t *testing.T) {
	w := newTestMuSig2Wallet(t)
	other, _ := newSoftwareParticipant(t, "other")
	packet, leafHash, scriptConfig := newSeveralSpendPathsPSBT(t, w, other)
	input := &packet.Inputs[0]

	infos, err := psbt.MuSig2SigningInfos(packet, 0, w.device.pubKey)
	require.NoError(t, err)
	require.Len(t, infos, 2)

	// The nonce round covers both spend paths, the key path first.
	fingerprint := w.device.fingerprint
	options := &PSBTSignOptions{ForceScriptConfig: scriptConfig}
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepNonce)
	result, err := newBTCTxFromPSBT(
		btcMuSig2MinVersion, packet, fingerprint, options,
	)
	require.NoError(t, err)
	contexts := result.tx.Inputs[0].Input.Musig2
	require.Len(t, contexts, 2)
	require.Equal(t, "musig(@0,@1)/**", contexts[0].KeyExpression)
	require.Nil(t, contexts[0].TapleafHash)
	require.Equal(t, "musig(@0,@2)/**", contexts[1].KeyExpression)
	require.Equal(t, leafHash, contexts[1].TapleafHash)

	// The key path partner contributes its nonce: the key path is signed,
	// the leaf skipped.
	for _, info := range infos {
		nonces, err := musig2.GenNonces(
			musig2.WithPublicKey(w.device.pubKey),
		)
		require.NoError(t, err)
		input.MuSig2PubNonces = append(
			input.MuSig2PubNonces, &psbt.MuSig2PubNonce{
				PubKey:       w.device.pubKey,
				AggregateKey: info.ContextKey,
				TapLeafHash:  info.TapLeafHash,
				PubNonce:     nonces.PubNonce,
			},
		)
	}
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepWait)
	(&softwareSigner{key: w.softwareKey}).nonce(t, packet)
	requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepSign)
	require.NoError(t, result.addMuSig2Options(packet, &PSBTMuSig2Options{
		Phase: messages.BTCMuSig2Init_SIGN,
	}))
	keyPath := result.tx.MuSig2.Nonces[BTCMuSig2Context{}]
	require.False(t, keyPath.Skip)
	require.Len(t, keyPath.Nonces, 2)
	require.Nil(t, keyPath.TapleafHash)
	leaf := result.tx.MuSig2.Nonces[BTCMuSig2Context{Position: 1}]
	require.True(t, leaf.Skip)
	require.Empty(t, leaf.Nonces)
	require.Equal(t, leafHash, leaf.TapleafHash)
}

// leafScriptConfig returns the policy with our key in the key path aggregate
// and in a leaf aggregate with the other participant.
func leafScriptConfig(t *testing.T, w *muSig2Wallet,
	other muSig2Participant) *messages.BTCScriptConfigWithKeypath {

	t.Helper()

	config := w.scriptConfig.ScriptConfig.GetPolicy()
	xpub, err := NewXPub(other.xpub.String())
	require.NoError(t, err)
	keys := slices.Concat(config.Keys, []*messages.KeyOriginInfo{{
		RootFingerprint: other.fingerprint,
		Keypath:         muSig2TestKeypath,
		Xpub:            xpub,
	}})

	return &messages.BTCScriptConfigWithKeypath{
		ScriptConfig: NewBTCScriptConfigPolicy(
			"tr(musig(@0,@1)/**,pk(musig(@0,@2)/**))", keys,
		),
		Keypath: muSig2TestKeypath,
	}
}
