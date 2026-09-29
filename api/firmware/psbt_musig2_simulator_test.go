// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// muSig2TestKeypath is the BIP-48 Taproot account path of both participants.
var muSig2TestKeypath = []uint32{
	48 + hardenedKeyStart, 1 + hardenedKeyStart, 0 + hardenedKeyStart,
	3 + hardenedKeyStart,
}

// muSig2Participant is one participant of the test wallet.
type muSig2Participant struct {
	fingerprint []byte
	xpub        *hdkeychain.ExtendedKey
	pubKey      *btcec.PublicKey
}

// muSig2Wallet is a registered tr(musig(@0,@1)/**) wallet of the simulator and
// a software cosigner.
type muSig2Wallet struct {
	device       muSig2Participant
	software     muSig2Participant
	softwareKey  *btcec.PrivateKey
	sorted       []*btcec.PublicKey
	aggregate    *btcec.PublicKey
	scriptConfig *messages.BTCScriptConfigWithKeypath
}

// newMuSig2Wallet sets up the software cosigner and registers the wallet
// policy on the device.
func newMuSig2Wallet(t *testing.T, device *Device) *muSig2Wallet {
	t.Helper()

	var wallet muSig2Wallet

	deviceFingerprint, err := device.RootFingerprint()
	require.NoError(t, err)
	deviceXPubStr, err := device.BTCXPub(
		messages.BTCCoin_TBTC, muSig2TestKeypath,
		messages.BTCPubRequest_TPUB, false,
	)
	require.NoError(t, err)
	deviceXPub, err := hdkeychain.NewKeyFromString(deviceXPubStr)
	require.NoError(t, err)
	devicePubKey, err := deviceXPub.ECPubKey()
	require.NoError(t, err)
	wallet.device = muSig2Participant{
		deviceFingerprint, deviceXPub, devicePubKey,
	}
	wallet.software, wallet.softwareKey = newSoftwareParticipant(
		t, "bitbox02-api-go musig2 cosigner",
	)
	wallet.complete(t)
	require.NoError(t, device.BTCRegisterScriptConfig(
		messages.BTCCoin_TBTC, wallet.scriptConfig.ScriptConfig, nil,
		"MuSig2 wallet",
	))

	return &wallet
}

// newSoftwareParticipant derives a participant at the test keypath from a seed
// derived from the label.
func newSoftwareParticipant(t *testing.T, label string) (muSig2Participant,
	*btcec.PrivateKey) {

	t.Helper()

	seed := sha256.Sum256([]byte(label))
	master, err := hdkeychain.NewMaster(seed[:], &chaincfg.TestNet3Params)
	require.NoError(t, err)
	masterPubKey, err := master.ECPubKey()
	require.NoError(t, err)
	account := master
	for _, child := range muSig2TestKeypath {
		account, err = account.Derive(child)
		require.NoError(t, err)
	}
	key, err := account.ECPrivKey()
	require.NoError(t, err)
	xpub, err := account.Neuter()
	require.NoError(t, err)

	return muSig2Participant{
		address.Hash160(masterPubKey.SerializeCompressed())[:4],
		xpub, key.PubKey(),
	}, key
}

// complete derives the aggregate and the policy of the wallet from its
// participants.
func (wallet *muSig2Wallet) complete(t *testing.T) {
	t.Helper()

	// musig() aggregates the participants sorted (BIP-390).
	wallet.sorted = []*btcec.PublicKey{
		wallet.device.pubKey, wallet.software.pubKey,
	}
	slices.SortFunc(wallet.sorted, func(a, b *btcec.PublicKey) int {
		return bytes.Compare(
			a.SerializeCompressed(), b.SerializeCompressed(),
		)
	})
	aggKey, _, _, err := musig2.AggregateKeys(
		slices.Clone(wallet.sorted), false,
	)
	require.NoError(t, err)
	wallet.aggregate = aggKey.PreTweakedKey

	keys := make([]*messages.KeyOriginInfo, 0, 2)
	for _, participant := range []muSig2Participant{
		wallet.device, wallet.software,
	} {
		xpub, err := NewXPub(participant.xpub.String())
		require.NoError(t, err)
		keys = append(keys, &messages.KeyOriginInfo{
			RootFingerprint: participant.fingerprint,
			Keypath:         muSig2TestKeypath,
			Xpub:            xpub,
		})
	}
	wallet.scriptConfig = &messages.BTCScriptConfigWithKeypath{
		ScriptConfig: NewBTCScriptConfigPolicy(
			"tr(musig(@0,@1)/**)", keys,
		),
		Keypath: muSig2TestKeypath,
	}
}

// derivations returns the BIP-373 key path metadata of the wallet address at
// the given branch and index, as a descriptor wallet records it.
func (w *muSig2Wallet) derivations(t *testing.T, branch,
	index uint32) ([]byte, []*psbt.TaprootBip32Derivation, []byte) {

	t.Helper()

	root, err := hdkeychain.NewMuSig2Key(
		w.aggregate, &chaincfg.TestNet3Params,
	)
	require.NoError(t, err)
	child, err := root.Derive(branch)
	require.NoError(t, err)
	child, err = child.Derive(index)
	require.NoError(t, err)
	internalKey, err := child.ECPubKey()
	require.NoError(t, err)

	derivations := []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey: schnorr.SerializePubKey(internalKey),
		MasterKeyFingerprint: fingerprintUint32(address.Hash160(
			w.aggregate.SerializeCompressed(),
		)[:4]),
		Bip32Path: []uint32{branch, index},
	}}
	for _, participant := range []muSig2Participant{w.device, w.software} {
		derivations = append(derivations, &psbt.TaprootBip32Derivation{
			XOnlyPubKey:          schnorr.SerializePubKey(participant.pubKey),
			MasterKeyFingerprint: fingerprintUint32(participant.fingerprint),
			Bip32Path:            muSig2TestKeypath,
		})
	}

	outputKey := txscript.ComputeTaprootKeyNoScript(internalKey)
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	return schnorr.SerializePubKey(internalKey), derivations, pkScript
}

// newPSBT returns a PSBT spending a wallet UTXO at /0/0 to an external output
// and a change output at /1/7.
func (w *muSig2Wallet) newPSBT(t *testing.T) *psbt.Packet {
	t.Helper()

	inputInternalKey, inputDerivations, inputPkScript := w.derivations(t, 0, 0)
	changeInternalKey, changeDerivations, changePkScript := w.derivations(t, 1, 7)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: chainhash.Hash{1}},
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(wire.NewTxOut(
		60_000, append([]byte{0x00, 0x14}, bytes.Repeat([]byte{5}, 20)...),
	))
	tx.AddTxOut(wire.NewTxOut(39_000, changePkScript))

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	participants := &psbt.MuSig2Participants{
		AggregateKey: w.aggregate,
		Keys:         w.sorted,
	}

	input := &packet.Inputs[0]
	input.WitnessUtxo = wire.NewTxOut(100_000, inputPkScript)
	input.TaprootInternalKey = inputInternalKey
	input.TaprootBip32Derivation = inputDerivations
	input.MuSig2Participants = []*psbt.MuSig2Participants{participants}

	output := &packet.Outputs[1]
	output.TaprootInternalKey = changeInternalKey
	output.TaprootBip32Derivation = changeDerivations
	output.MuSig2Participants = []*psbt.MuSig2Participants{participants}

	return packet
}

// softwareSigner is the software cosigner. It keeps its secret nonce between
// its two contributions.
type softwareSigner struct {
	key      *btcec.PrivateKey
	secNonce *[musig2.SecNonceSize]byte
}

// nonce adds the software cosigner's public nonce to the input.
func (s *softwareSigner) nonce(t *testing.T, packet *psbt.Packet) {
	t.Helper()

	info := muSig2SigningInfo(t, packet, s.key.PubKey())
	nonces, err := musig2.GenNonces(musig2.WithPublicKey(s.key.PubKey()))
	require.NoError(t, err)
	s.secNonce = &nonces.SecNonce

	updater, err := psbt.NewUpdater(packet)
	require.NoError(t, err)
	require.NoError(t, updater.AddInMuSig2PubNonce(0, &psbt.MuSig2PubNonce{
		PubKey:       s.key.PubKey(),
		AggregateKey: info.ContextKey,
		TapLeafHash:  info.TapLeafHash,
		PubNonce:     nonces.PubNonce,
	}))
}

// sign adds the software cosigner's partial signature to the input, once
// every participant's nonce is present.
func (s *softwareSigner) sign(t *testing.T, packet *psbt.Packet) {
	t.Helper()

	info := muSig2SigningInfo(t, packet, s.key.PubKey())
	var pubNonces [][musig2.PubNonceSize]byte
	for _, participant := range info.Participants.Keys {
		index := slices.IndexFunc(packet.Inputs[0].MuSig2PubNonces,
			func(nonce *psbt.MuSig2PubNonce) bool {
				return nonce.PubKey.IsEqual(participant)
			},
		)
		require.GreaterOrEqual(t, index, 0)
		pubNonces = append(
			pubNonces, packet.Inputs[0].MuSig2PubNonces[index].PubNonce,
		)
	}
	combinedNonce, err := musig2.AggregateNonces(pubNonces)
	require.NoError(t, err)

	partialSig, err := musig2.Sign(
		*s.secNonce, s.key, combinedNonce,
		slices.Clone(info.Participants.Keys), info.SigHash,
		musig2.WithTweaks(info.Tweaks...),
	)
	require.NoError(t, err)
	s.secNonce = nil

	updater, err := psbt.NewUpdater(packet)
	require.NoError(t, err)
	_, err = updater.SignMuSig2(0, &psbt.MuSig2PartialSig{
		PubKey:       s.key.PubKey(),
		AggregateKey: info.ContextKey,
		TapLeafHash:  info.TapLeafHash,
		PartialSig:   *partialSig,
	})
	require.NoError(t, err)
}

func muSig2SigningInfo(t *testing.T, packet *psbt.Packet,
	participant *btcec.PublicKey) *psbt.MuSig2SigningInfo {

	t.Helper()

	infos, err := psbt.MuSig2SigningInfos(packet, 0, participant)
	require.NoError(t, err)
	require.Len(t, infos, 1)

	return infos[0]
}

// requireMuSig2Step asserts what the device has to do next.
func requireMuSig2Step(t *testing.T, packet *psbt.Packet,
	fingerprint []byte, want PSBTMuSig2Step) {

	t.Helper()

	step, err := BTCPSBTMuSig2Step(packet, fingerprint)
	require.NoError(t, err)
	require.Equal(t, want, step)
}

// requireValidSpend finalizes the PSBT and runs the transaction through the
// script engine.
func requireValidSpend(t *testing.T, packet *psbt.Packet) {
	t.Helper()

	require.NoError(t, psbt.MaybeFinalizeAll(packet))
	tx, err := psbt.Extract(packet)
	require.NoError(t, err)
	require.Len(t, tx.TxIn[0].Witness, 1)

	prevOut := packet.Inputs[0].WitnessUtxo
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	engine, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prevOut.Value, fetcher,
	)
	require.NoError(t, err)
	require.NoError(t, engine.Execute())
}

// TestSimulatorBTCSignPSBTMuSig2 signs a key path spend of a
// tr(musig(@0,@1)/**) wallet with the device and a software cosigner, in both
// ways the device can take part: as the last signer in a single round, and in
// two rounds around the software cosigner's contribution.
func TestSimulatorBTCSignPSBTMuSig2(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, _ *simulatorStdout) {
		t.Helper()
		if !device.SupportsBTCMuSig2() {
			t.Skip("simulator does not support MuSig2")
		}

		wallet := newMuSig2Wallet(t, device)
		fingerprint := wallet.device.fingerprint
		options := func(phase messages.BTCMuSig2Init_Phase,
			sessionID []byte) *PSBTSignOptions {

			return &PSBTSignOptions{
				ForceScriptConfig: wallet.scriptConfig,
				MuSig2: &PSBTMuSig2Options{
					Phase:     phase,
					SessionID: sessionID,
				},
			}
		}

		t.Run("single round", func(t *testing.T) {
			packet := wallet.newPSBT(t)
			software := &softwareSigner{key: wallet.softwareKey}

			software.nonce(t, packet)
			requireMuSig2Step(
				t, packet, fingerprint, PSBTMuSig2StepNonceAndSign,
			)
			opts := options(messages.BTCMuSig2Init_NONCE_AND_SIGN, nil)
			require.NoError(t, device.BTCSignPSBT(
				messages.BTCCoin_TBTC, packet, opts,
			))
			require.Len(t, opts.MuSig2.SessionID, muSig2SessionIDSize)
			requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepDone)

			software.sign(t, packet)
			requireValidSpend(t, packet)
		})

		t.Run("two rounds", func(t *testing.T) {
			packet := wallet.newPSBT(t)
			software := &softwareSigner{key: wallet.softwareKey}

			requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepNonce)
			opts := options(messages.BTCMuSig2Init_NONCE, nil)
			require.NoError(t, device.BTCSignPSBT(
				messages.BTCCoin_TBTC, packet, opts,
			))
			requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepWait)

			// The software cosigner contributes last.
			software.nonce(t, packet)
			software.sign(t, packet)
			requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepSign)

			opts = options(messages.BTCMuSig2Init_SIGN, opts.MuSig2.SessionID)
			require.NoError(t, device.BTCSignPSBT(
				messages.BTCCoin_TBTC, packet, opts,
			))
			requireMuSig2Step(t, packet, fingerprint, PSBTMuSig2StepDone)
			requireValidSpend(t, packet)
		})

		t.Run("abort", func(t *testing.T) {
			packet := wallet.newPSBT(t)
			opts := options(messages.BTCMuSig2Init_NONCE, nil)
			require.NoError(t, device.BTCSignPSBT(
				messages.BTCCoin_TBTC, packet, opts,
			))
			require.NoError(t, device.BTCMuSig2Abort(opts.MuSig2.SessionID))

			// The aborted session cannot sign anymore.
			software := &softwareSigner{key: wallet.softwareKey}
			software.nonce(t, packet)
			opts = options(messages.BTCMuSig2Init_SIGN, opts.MuSig2.SessionID)
			require.Error(t, device.BTCSignPSBT(
				messages.BTCCoin_TBTC, packet, opts,
			))
		})
	})
}
