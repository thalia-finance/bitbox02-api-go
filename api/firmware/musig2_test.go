// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"testing"

	"github.com/BitBoxSwiss/bitbox02-api-go/api/common"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/messages"
	"github.com/BitBoxSwiss/bitbox02-api-go/api/firmware/mocks"
	"github.com/BitBoxSwiss/bitbox02-api-go/util/semver"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

var (
	testMuSig2SessionID = bytes.Repeat([]byte{'s'}, muSig2SessionIDSize)
	testMuSig2Key       = append([]byte{0x02}, bytes.Repeat([]byte{'k'}, 32)...)
	testMuSig2Peer      = append([]byte{0x03}, bytes.Repeat([]byte{'p'}, 32)...)
)

// testMuSig2Context is the BIP-373 context of every MuSig2 input in the tests
// below.
func testMuSig2Context() *messages.BTCMuSig2Input {
	return &messages.BTCMuSig2Input{
		KeyExpression:      "musig(@0,@1)/**",
		AggregateKey:       testMuSig2Key,
		ParticipantPubkeys: [][]byte{testMuSig2Key, testMuSig2Peer},
		ContextKey:         testMuSig2Key,
	}
}

// testMuSig2Tx returns a transaction with two MuSig2 inputs and one output,
// and the matching script configs.
func testMuSig2Tx(options *BTCMuSig2Options) ([]*messages.BTCScriptConfigWithKeypath,
	*BTCTx) {

	scriptConfigs := []*messages.BTCScriptConfigWithKeypath{{
		ScriptConfig: NewBTCScriptConfigPolicy(
			"tr(musig(@0,@1)/**)", nil,
		),
	}}
	tx := &BTCTx{
		Version:  2,
		Outputs:  []*messages.BTCSignOutputRequest{{Value: 1}},
		MuSig2:   options,
		Locktime: 0,
	}
	for range 2 {
		tx.Inputs = append(tx.Inputs, &BTCTxInput{
			Input: &messages.BTCSignInputRequest{
				Keypath: []uint32{0, 0},
				Musig2:  testMuSig2Context(),
			},
		})
	}

	return scriptConfigs, tx
}

// testMuSig2Contribution is the device's contribution to one MuSig2 input.
func testMuSig2Contribution(index uint32, nonce,
	partialSig bool) *messages.BTCMuSig2Result {

	result := &messages.BTCMuSig2Result{
		InputIndex:        index,
		ParticipantPubkey: testMuSig2Key,
		ContextKey:        testMuSig2Key,
	}
	if nonce {
		result.PublicNonce = bytes.Repeat([]byte{'n'}, muSig2PubNonceSize)
	}
	if partialSig {
		result.PartialSignature = bytes.Repeat(
			[]byte{'p'}, muSig2PartialSigSize,
		)
	}

	return result
}

// muSig2Exchange is one expected request and the scripted device response.
type muSig2Exchange struct {
	request string
	next    *messages.BTCSignNextResponse
}

func muSig2Next(typ messages.BTCSignNextResponse_Type, index uint32,
	result *messages.BTCMuSig2Result,
	sessionID []byte) *messages.BTCSignNextResponse {

	return &messages.BTCSignNextResponse{
		Type:            typ,
		Index:           index,
		Musig2Result:    result,
		Musig2SessionId: sessionID,
	}
}

// muSig2Exchanges scripts the firmware's side of a MuSig2 call over the
// transaction of testMuSig2Tx. A contribution for an input rides on the
// response to the request that completes it: the pass two input request in
// the nonce round, the nonces request otherwise. The last one arrives on DONE.
func muSig2Exchanges(nonce, partialSig bool) []muSig2Exchange {
	exchanges := []muSig2Exchange{
		{"btc_sign_init", muSig2Next(
			messages.BTCSignNextResponse_INPUT, 0, nil,
			testMuSig2SessionID,
		)},
		{"btc_sign_input", muSig2Next(
			messages.BTCSignNextResponse_INPUT, 1, nil, nil,
		)},
		{"btc_sign_input", muSig2Next(
			messages.BTCSignNextResponse_OUTPUT, 0, nil, nil,
		)},
		{"btc_sign_output", muSig2Next(
			messages.BTCSignNextResponse_INPUT, 0, nil, nil,
		)},
	}
	for index := range uint32(2) {
		request := "btc_sign_input"
		if partialSig {
			exchanges = append(exchanges, muSig2Exchange{
				request, muSig2Next(
					messages.BTCSignNextResponse_MUSIG2_NONCES,
					index, nil, nil,
				),
			})
			request = "musig2_nonces"
		}

		typ := messages.BTCSignNextResponse_INPUT
		var sessionID []byte
		if index == 1 {
			typ = messages.BTCSignNextResponse_DONE
			sessionID = testMuSig2SessionID
		}
		exchanges = append(exchanges, muSig2Exchange{
			request, muSig2Next(
				typ, 1, testMuSig2Contribution(
					index, nonce, partialSig,
				), sessionID,
			),
		})
	}

	return exchanges
}

// requestName returns the name of the sign request, looking into the nested
// BTC request.
func requestName(t *testing.T, request *messages.Request) string {
	t.Helper()

	switch r := request.Request.(type) {
	case *messages.Request_BtcSignInit:
		return "btc_sign_init"
	case *messages.Request_BtcSignInput:
		return "btc_sign_input"
	case *messages.Request_BtcSignOutput:
		return "btc_sign_output"
	case *messages.Request_Btc:
		if _, ok := r.Btc.Request.(*messages.BTCRequest_Musig2Nonces); ok {
			return "musig2_nonces"
		}
	}
	require.Failf(t, "unexpected request", "%v", request)

	return ""
}

// newMuSig2Device returns a device of the given version that answers with the
// given exchanges, and records the requests it receives.
func newMuSig2Device(t *testing.T, version *semver.SemVer,
	exchanges []muSig2Exchange) (*Device, *[]*messages.Request) {

	t.Helper()

	var requests []*messages.Request
	device := newDevice(
		t, version, common.ProductBitBox02Multi, &mocks.Communication{},
		func(request *messages.Request) *messages.Response {
			require.NotEmpty(t, exchanges, "unexpected request")
			exchange := exchanges[0]
			exchanges = exchanges[1:]

			require.Equal(t, exchange.request, requestName(t, request))
			requests = append(requests, request)

			if _, ok := request.Request.(*messages.Request_Btc); ok {
				return &messages.Response{
					Response: &messages.Response_Btc{
						Btc: &messages.BTCResponse{
							Response: &messages.BTCResponse_SignNext{
								SignNext: exchange.next,
							},
						},
					},
				}
			}
			return &messages.Response{
				Response: &messages.Response_BtcSignNext{
					BtcSignNext: exchange.next,
				},
			}
		},
	)
	t.Cleanup(func() {
		require.Empty(t, exchanges, "not all exchanges happened")
	})

	return device, &requests
}

// testMuSig2Nonces returns nonces requests for both inputs of testMuSig2Tx.
func testMuSig2Nonces() map[uint32]*messages.BTCMuSig2NoncesRequest {
	nonces := make(map[uint32]*messages.BTCMuSig2NoncesRequest)
	for index := range uint32(2) {
		nonces[index] = &messages.BTCMuSig2NoncesRequest{
			InputIndex: index,
			ContextKey: testMuSig2Key,
			Nonces: []*messages.BTCMuSig2Nonce{{
				ParticipantPubkey: testMuSig2Peer,
				PublicNonce: bytes.Repeat(
					[]byte{'m'}, muSig2PubNonceSize,
				),
			}},
		}
	}

	return nonces
}

// TestBTCSignMuSig2Phases asserts the host side of every MuSig2 phase: the
// session is announced and acknowledged, every input carries its context, the
// nonces requests are answered and every contribution is collected, including
// the one that arrives on DONE.
func TestBTCSignMuSig2Phases(t *testing.T) {
	tests := []struct {
		name       string
		options    *BTCMuSig2Options
		nonce      bool
		partialSig bool
	}{{
		name: "nonce",
		options: &BTCMuSig2Options{
			Phase: messages.BTCMuSig2Init_NONCE,
		},
		nonce: true,
	}, {
		name: "sign",
		options: &BTCMuSig2Options{
			Phase:     messages.BTCMuSig2Init_SIGN,
			SessionID: testMuSig2SessionID,
			Nonces:    testMuSig2Nonces(),
		},
		partialSig: true,
	}, {
		name: "nonce and sign",
		options: &BTCMuSig2Options{
			Phase:  messages.BTCMuSig2Init_NONCE_AND_SIGN,
			Nonces: testMuSig2Nonces(),
		},
		nonce:      true,
		partialSig: true,
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device, requests := newMuSig2Device(
				t, btcMuSig2MinVersion,
				muSig2Exchanges(test.nonce, test.partialSig),
			)
			scriptConfigs, tx := testMuSig2Tx(test.options)

			result, err := device.BTCSign(
				messages.BTCCoin_TBTC, scriptConfigs, nil, tx,
				messages.BTCSignInitRequest_DEFAULT,
			)
			require.NoError(t, err)
			require.Equal(t, testMuSig2SessionID, result.MuSig2SessionID)
			require.Len(t, result.MuSig2Results, 2)
			for index := range uint32(2) {
				require.True(t, proto.Equal(
					testMuSig2Contribution(
						index, test.nonce,
						test.partialSig,
					), result.MuSig2Results[index],
				))
				require.Empty(t, result.Signatures[index])
			}

			init := (*requests)[0].GetBtcSignInit().Musig2
			require.Equal(t, test.options.Phase, init.Phase)
			require.Equal(t, test.options.SessionID, init.SessionId)
			for _, request := range *requests {
				if input := request.GetBtcSignInput(); input != nil {
					require.True(t, proto.Equal(
						testMuSig2Context(), input.Musig2,
					))
					require.Nil(t, input.HostNonceCommitment)
				}
				nonces := request.GetBtc().GetMusig2Nonces()
				if nonces != nil {
					require.True(t, proto.Equal(
						test.options.Nonces[nonces.InputIndex],
						nonces,
					))
				}
			}
		})
	}
}

// TestBTCSignMuSig2NotAcknowledged asserts that no input is sent to a device
// that does not acknowledge the MuSig2 session, which is what firmware without
// MuSig2 support does.
func TestBTCSignMuSig2NotAcknowledged(t *testing.T) {
	exchanges := muSig2Exchanges(true, false)[:1]
	exchanges[0].next.Musig2SessionId = nil
	device, requests := newMuSig2Device(t, btcMuSig2MinVersion, exchanges)
	scriptConfigs, tx := testMuSig2Tx(&BTCMuSig2Options{
		Phase: messages.BTCMuSig2Init_NONCE,
	})

	_, err := device.BTCSign(
		messages.BTCCoin_TBTC, scriptConfigs, nil, tx,
		messages.BTCSignInitRequest_DEFAULT,
	)
	require.ErrorContains(t, err, "did not acknowledge")
	require.Len(t, *requests, 1)
}

// TestBTCSignMuSig2BadContributions asserts that contributions that do not
// match the transaction or the phase are rejected.
func TestBTCSignMuSig2BadContributions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(exchanges []muSig2Exchange)
		errMsg string
	}{{
		name: "missing on done",
		mutate: func(exchanges []muSig2Exchange) {
			exchanges[len(exchanges)-1].next.Musig2Result = nil
		},
		errMsg: "missing MuSig2 contribution",
	}, {
		name: "wrong session on done",
		mutate: func(exchanges []muSig2Exchange) {
			exchanges[len(exchanges)-1].next.Musig2SessionId = nil
		},
		errMsg: "different MuSig2 session",
	}, {
		name: "duplicate",
		mutate: func(exchanges []muSig2Exchange) {
			exchanges[len(exchanges)-1].next.Musig2Result.InputIndex = 0
		},
		errMsg: "duplicate",
	}, {
		name: "wrong context",
		mutate: func(exchanges []muSig2Exchange) {
			result := exchanges[len(exchanges)-1].next.Musig2Result
			result.TapleafHash = make([]byte, 32)
		},
		errMsg: "does not match its context",
	}, {
		name: "not a participant",
		mutate: func(exchanges []muSig2Exchange) {
			result := exchanges[len(exchanges)-1].next.Musig2Result
			result.ParticipantPubkey = testMuSig2Context().ContextKey[1:]
		},
		errMsg: "does not match its context",
	}, {
		name: "partial signature in nonce round",
		mutate: func(exchanges []muSig2Exchange) {
			result := exchanges[len(exchanges)-1].next.Musig2Result
			result.PartialSignature = make([]byte, 32)
		},
		errMsg: "does not match phase",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exchanges := muSig2Exchanges(true, false)
			test.mutate(exchanges)
			device, _ := newMuSig2Device(
				t, btcMuSig2MinVersion, exchanges,
			)
			scriptConfigs, tx := testMuSig2Tx(&BTCMuSig2Options{
				Phase: messages.BTCMuSig2Init_NONCE,
			})

			_, err := device.BTCSign(
				messages.BTCCoin_TBTC, scriptConfigs, nil, tx,
				messages.BTCSignInitRequest_DEFAULT,
			)
			require.ErrorContains(t, err, test.errMsg)
		})
	}
}

// TestBTCSignMuSig2InvalidOptions asserts that inconsistent MuSig2 options are
// rejected before anything is sent to the device.
func TestBTCSignMuSig2InvalidOptions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(tx *BTCTx)
		errMsg string
	}{{
		name:   "no options",
		mutate: func(tx *BTCTx) { tx.MuSig2 = nil },
		errMsg: "no MuSig2 options",
	}, {
		name: "no MuSig2 inputs",
		mutate: func(tx *BTCTx) {
			for _, input := range tx.Inputs {
				input.Input.Musig2 = nil
			}
		},
		errMsg: "no MuSig2 inputs",
	}, {
		name: "abort",
		mutate: func(tx *BTCTx) {
			tx.MuSig2.Phase = messages.BTCMuSig2Init_ABORT
		},
		errMsg: "BTCMuSig2Abort",
	}, {
		name: "sign without session",
		mutate: func(tx *BTCTx) {
			tx.MuSig2.Phase = messages.BTCMuSig2Init_SIGN
			tx.MuSig2.Nonces = testMuSig2Nonces()
		},
		errMsg: "invalid MuSig2 session ID",
	}, {
		name: "nonce round with session",
		mutate: func(tx *BTCTx) {
			tx.MuSig2.SessionID = testMuSig2SessionID
		},
		errMsg: "invalid MuSig2 session ID",
	}, {
		name: "nonces in nonce round",
		mutate: func(tx *BTCTx) {
			tx.MuSig2.Nonces = testMuSig2Nonces()
		},
		errMsg: "invalid MuSig2 nonces",
	}, {
		name: "missing nonces",
		mutate: func(tx *BTCTx) {
			tx.MuSig2.Phase = messages.BTCMuSig2Init_NONCE_AND_SIGN
			tx.MuSig2.Nonces = testMuSig2Nonces()
			delete(tx.MuSig2.Nonces, 1)
		},
		errMsg: "invalid MuSig2 nonces",
	}, {
		name: "bip322",
		mutate: func(tx *BTCTx) {
			tx.Bip322Message = []byte("message")
		},
		errMsg: "BIP-322",
	}, {
		name: "silent payment",
		mutate: func(tx *BTCTx) {
			tx.Outputs[0].SilentPayment = &messages.BTCSignOutputRequest_SilentPayment{}
		},
		errMsg: "silent payments",
	}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			device, _ := newMuSig2Device(t, btcMuSig2MinVersion, nil)
			scriptConfigs, tx := testMuSig2Tx(&BTCMuSig2Options{
				Phase: messages.BTCMuSig2Init_NONCE,
			})
			test.mutate(tx)

			_, err := device.BTCSign(
				messages.BTCCoin_TBTC, scriptConfigs, nil, tx,
				messages.BTCSignInitRequest_DEFAULT,
			)
			require.ErrorContains(t, err, test.errMsg)
		})
	}

	// Firmware without MuSig2 support is not even asked.
	device, _ := newMuSig2Device(t, semver.NewSemVer(9, 27, 1), nil)
	scriptConfigs, tx := testMuSig2Tx(&BTCMuSig2Options{
		Phase: messages.BTCMuSig2Init_NONCE,
	})
	_, err := device.BTCSign(
		messages.BTCCoin_TBTC, scriptConfigs, nil, tx,
		messages.BTCSignInitRequest_DEFAULT,
	)
	require.Equal(t, UnsupportedError(btcMuSig2MinVersion.String()), err)
	require.False(t, device.SupportsBTCMuSig2())
	require.Equal(
		t, UnsupportedError(btcMuSig2MinVersion.String()),
		device.BTCMuSig2Abort(testMuSig2SessionID),
	)
}

// TestBTCMuSig2Abort asserts the abort request and its response handling.
func TestBTCMuSig2Abort(t *testing.T) {
	device, requests := newMuSig2Device(
		t, btcMuSig2MinVersion, []muSig2Exchange{{
			"btc_sign_init", muSig2Next(
				messages.BTCSignNextResponse_DONE, 0, nil, nil,
			),
		}, {
			"btc_sign_init", muSig2Next(
				messages.BTCSignNextResponse_INPUT, 0, nil, nil,
			),
		}},
	)
	require.True(t, device.SupportsBTCMuSig2())

	require.NoError(t, device.BTCMuSig2Abort(testMuSig2SessionID))
	init := (*requests)[0].GetBtcSignInit().Musig2
	require.Equal(t, messages.BTCMuSig2Init_ABORT, init.Phase)
	require.Equal(t, testMuSig2SessionID, init.SessionId)

	require.ErrorContains(
		t, device.BTCMuSig2Abort(testMuSig2SessionID),
		"unexpected response",
	)
}
