// SPDX-License-Identifier: Apache-2.0

package firmware

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/BitBoxSwiss/bitboxsync-client-go/protocol"
	"github.com/stretchr/testify/require"
)

func requireBitBoxSyncSignature(t *testing.T, identity *BitBoxSyncIdentity, payload, signature []byte) {
	t.Helper()
	require.Len(t, signature, ed25519.SignatureSize)
	require.True(t, ed25519.Verify(identity.AuthPublicKey, payload, signature))
}

func mustDecodeHex(t *testing.T, input string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(input)
	require.NoError(t, err)
	return bytes
}

func fixedBitBoxSyncIdentity(t *testing.T) *BitBoxSyncIdentity {
	t.Helper()
	return &BitBoxSyncIdentity{
		AuthPublicKey: ed25519.PublicKey(mustDecodeHex(t, "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")),
		WrapPublicKey: mustDecodeHex(t, "ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59"),
	}
}

func bitBoxSyncWrapPublicKey(t *testing.T, identity *BitBoxSyncIdentity) *ecdh.PublicKey {
	t.Helper()
	wrapPublicKey, err := ecdh.X25519().NewPublicKey(identity.WrapPublicKey)
	require.NoError(t, err)
	return wrapPublicKey
}

func TestBitBoxSyncPayloadVectors(t *testing.T) {
	identity := fixedBitBoxSyncIdentity(t)
	keyID := protocol.KeyIDFromAuthPublicKey(identity.AuthPublicKey)

	actionFields, err := protocol.CreateNamespaceInviteActionFields(
		bytes.Repeat([]byte{0x20}, bitBoxSyncNamespaceIDLen),
		bytes.Repeat([]byte{0x21}, bitBoxSyncInviteIDLen),
		bytes.Repeat([]byte{0x22}, bitBoxSyncInviteServerSecretHashLen),
		0x0102030405060708,
		10,
	)
	require.NoError(t, err)
	createPayload, err := protocol.SensitiveActionIntent(
		bytes.Repeat([]byte{0x13}, bitBoxSyncChallengeLength),
		protocol.SensitiveActionCreateNamespaceInvite,
		protocol.IdentityKindKeystore,
		keyID[:],
		actionFields,
	)
	require.NoError(t, err)
	require.Equal(t,
		mustDecodeHex(t, "626974626f7873796e632d696e74656e7401030213131313131313131313131313131313131313131313131313131313131313130134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e2020202020202020202020202020202021212121212121212121212121212121222222222222222222222222222222222222222222222222222222222222222201020304050607080000000a"),
		createPayload,
	)

	serverOrigin := "https://sync.example"
	serverOriginHash, err := protocol.ServerOriginHash(serverOrigin)
	require.NoError(t, err)
	joinPayload, err := protocol.JoinRequestPayload(
		protocol.IdentityKindKeystore,
		bytes.Repeat([]byte{0x20}, bitBoxSyncNamespaceIDLen),
		bytes.Repeat([]byte{0x21}, bitBoxSyncInviteIDLen),
		serverOriginHash,
		keyID[:],
		identity.AuthPublicKey,
		bitBoxSyncWrapPublicKey(t, identity),
		0x0102030405060708,
	)
	require.NoError(t, err)
	require.Equal(t,
		mustDecodeHex(t, "626974626f7873796e632d6a6f696e2d72657175657374012020202020202020202020202020202021212121212121212121212121212121ff93ec0a47d8af4a6dc161a681c24d41e1a2ddb9ea6d5c9dc55b106f4c1b6c150134750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d590102030405060708"),
		joinPayload,
	)
}

func TestBitBoxSyncHostSideValidation(t *testing.T) {
	device := &Device{}
	challenge := bytes.Repeat([]byte{0x01}, bitBoxSyncChallengeLength)
	namespaceID := bytes.Repeat([]byte{0x02}, bitBoxSyncNamespaceIDLen)
	inviteID := bytes.Repeat([]byte{0x03}, bitBoxSyncInviteIDLen)
	inviteServerSecretHash := bytes.Repeat([]byte{0x04}, bitBoxSyncInviteServerSecretHashLen)

	tests := []struct {
		name          string
		sign          func() error
		errorContains string
	}{
		{
			name: "create namespace invite challenge",
			sign: func() error {
				_, err := device.BitBoxSyncSignCreateNamespaceInviteIntent(
					challenge[:bitBoxSyncChallengeLength-1],
					namespaceID,
					inviteID,
					inviteServerSecretHash,
					123,
					1,
				)
				return err
			},
			errorContains: "challenge",
		},
		{
			name: "create namespace invite namespace ID",
			sign: func() error {
				_, err := device.BitBoxSyncSignCreateNamespaceInviteIntent(
					challenge,
					namespaceID[:bitBoxSyncNamespaceIDLen-1],
					inviteID,
					inviteServerSecretHash,
					123,
					1,
				)
				return err
			},
			errorContains: "namespace ID",
		},
		{
			name: "create namespace invite ID",
			sign: func() error {
				_, err := device.BitBoxSyncSignCreateNamespaceInviteIntent(
					challenge,
					namespaceID,
					inviteID[:bitBoxSyncInviteIDLen-1],
					inviteServerSecretHash,
					123,
					1,
				)
				return err
			},
			errorContains: "invite ID",
		},
		{
			name: "create namespace invite secret hash",
			sign: func() error {
				_, err := device.BitBoxSyncSignCreateNamespaceInviteIntent(
					challenge,
					namespaceID,
					inviteID,
					inviteServerSecretHash[:bitBoxSyncInviteServerSecretHashLen-1],
					123,
					1,
				)
				return err
			},
			errorContains: "invite server secret hash",
		},
		{
			name: "join request namespace ID",
			sign: func() error {
				_, err := device.BitBoxSyncSignJoinRequestIntent(
					namespaceID[:bitBoxSyncNamespaceIDLen-1],
					inviteID,
					"not host-validated",
					123,
				)
				return err
			},
			errorContains: "namespace ID",
		},
		{
			name: "join request invite ID",
			sign: func() error {
				_, err := device.BitBoxSyncSignJoinRequestIntent(
					namespaceID,
					inviteID[:bitBoxSyncInviteIDLen-1],
					"not host-validated",
					123,
				)
				return err
			},
			errorContains: "invite ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sign()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestSimulatorBitBoxSyncIdentity(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		if !device.Version().AtLeast(bitBoxSyncMinVersion) {
			identity, err := device.BitBoxSyncIdentity()
			require.Nil(t, identity)
			require.EqualError(t, err, UnsupportedError(bitBoxSyncMinVersion.String()).Error())
			require.NotContains(t, stdOut.String(), "TITLE: BitBoxSync")
			return
		}

		identity, err := device.BitBoxSyncIdentity()
		require.NoError(t, err)
		require.Len(t, identity.AuthPublicKey, ed25519.PublicKeySize)
		require.Len(t, identity.WrapPublicKey, bitBoxSyncWrapPublicKeyLen)
		require.NotContains(t, stdOut.String(), "TITLE: BitBoxSync")
	})
}

func TestSimulatorBitBoxSyncSignaturesAndUnwrap(t *testing.T) {
	testInitializedSimulators(t, func(t *testing.T, device *Device, stdOut *simulatorStdout) {
		t.Helper()
		challenge := bytes.Repeat([]byte{0x42}, bitBoxSyncChallengeLength)
		namespaceID := bytes.Repeat([]byte{0x11}, bitBoxSyncNamespaceIDLen)
		if !device.Version().AtLeast(bitBoxSyncMinVersion) {
			_, err := device.BitBoxSyncSignLoginIntent(challenge)
			require.EqualError(t, err, UnsupportedError(bitBoxSyncMinVersion.String()).Error())

			_, err = device.BitBoxSyncUnwrapNamespaceDEK(namespaceID, bytes.Repeat([]byte{0x00}, bitBoxSyncWrappedDEKLenV1))
			require.EqualError(t, err, UnsupportedError(bitBoxSyncMinVersion.String()).Error())
			require.NotContains(t, stdOut.String(), "TITLE: BitBoxSync")
			return
		}

		identity, err := device.BitBoxSyncIdentity()
		require.NoError(t, err)
		keyID := protocol.KeyIDFromAuthPublicKey(identity.AuthPublicKey)
		wrapPublicKey := bitBoxSyncWrapPublicKey(t, identity)

		loginSig, err := device.BitBoxSyncSignLoginIntent(challenge)
		require.NoError(t, err)
		loginPayload, err := protocol.LoginIntent(
			challenge,
			protocol.IdentityKindKeystore,
			keyID[:],
			identity.AuthPublicKey,
			wrapPublicKey,
		)
		require.NoError(t, err)
		requireBitBoxSyncSignature(t, identity, loginPayload, loginSig)

		refreshSig, err := device.BitBoxSyncSignRefreshIntent(challenge)
		require.NoError(t, err)
		refreshPayload, err := protocol.RefreshIntent(challenge, protocol.IdentityKindKeystore, keyID[:])
		require.NoError(t, err)
		requireBitBoxSyncSignature(t, identity, refreshPayload, refreshSig)

		revokeSig, err := device.BitBoxSyncSignRevokeAllTokensIntent(challenge)
		require.NoError(t, err)
		revokePayload, err := protocol.SensitiveActionIntent(
			challenge,
			protocol.SensitiveActionRevokeAllTokens,
			protocol.IdentityKindKeystore,
			keyID[:],
			nil,
		)
		require.NoError(t, err)
		requireBitBoxSyncSignature(t, identity, revokePayload, revokeSig)

		inviteID := bytes.Repeat([]byte{0x33}, bitBoxSyncInviteIDLen)
		inviteServerSecretHash := bytes.Repeat([]byte{0x44}, bitBoxSyncInviteServerSecretHashLen)
		createInviteSig, err := device.BitBoxSyncSignCreateNamespaceInviteIntent(
			challenge,
			namespaceID,
			inviteID,
			inviteServerSecretHash,
			123456789,
			8,
		)
		require.NoError(t, err)
		createActionFields, err := protocol.CreateNamespaceInviteActionFields(
			namespaceID,
			inviteID,
			inviteServerSecretHash,
			123456789,
			8,
		)
		require.NoError(t, err)
		createInvitePayload, err := protocol.SensitiveActionIntent(
			challenge,
			protocol.SensitiveActionCreateNamespaceInvite,
			protocol.IdentityKindKeystore,
			keyID[:],
			createActionFields,
		)
		require.NoError(t, err)
		requireBitBoxSyncSignature(t, identity, createInvitePayload, createInviteSig)

		serverOrigin := "https://sync.example"
		joinRequestSig, err := device.BitBoxSyncSignJoinRequestIntent(namespaceID, inviteID, serverOrigin, 123456789)
		require.NoError(t, err)
		serverOriginHash, err := protocol.ServerOriginHash(serverOrigin)
		require.NoError(t, err)
		joinRequestPayload, err := protocol.JoinRequestPayload(
			protocol.IdentityKindKeystore,
			namespaceID,
			inviteID,
			serverOriginHash,
			keyID[:],
			identity.AuthPublicKey,
			wrapPublicKey,
			123456789,
		)
		require.NoError(t, err)
		requireBitBoxSyncSignature(
			t,
			identity,
			joinRequestPayload,
			joinRequestSig,
		)

		namespaceDEK := bytes.Repeat([]byte{0x22}, bitBoxSyncNamespaceDEKLen)
		wrappedDEK, err := protocol.WrapNamespaceDEK(wrapPublicKey, namespaceID, namespaceDEK)
		require.NoError(t, err)
		unwrappedDEK, err := device.BitBoxSyncUnwrapNamespaceDEK(namespaceID, wrappedDEK)
		require.NoError(t, err)
		require.Equal(t, namespaceDEK, unwrappedDEK)

		wrappedDEK[len(wrappedDEK)-1] ^= 0x01
		_, err = device.BitBoxSyncUnwrapNamespaceDEK(namespaceID, wrappedDEK)
		require.Error(t, err)

		stdout := stdOut.String()
		require.Contains(t, stdout, "TITLE: BitBoxSync")
		require.Contains(t, stdout, "BODY: Login")
		require.Contains(t, stdout, "BODY: Refresh session")
		require.Contains(t, stdout, "BODY: Revoke all sessions")
		require.Contains(t, stdout, "BODY: Create invite")
		require.Contains(t, stdout, "BODY: Join namespace")
	})
}
