package rlpx

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"

	"encoding/binary"
	G "eth_discover/global"
	"eth_discover/session"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

func DeserializePacket(data []byte, session *session.Session, found bool) (Packet, byte, error) {
	// 3 cases
	// we have received an auth message
	// we have received an auth-ack message
	// we have received a frame

	if !found {
		return handleAuthMessage(data, session)
	} else if !session.IsActive() {
		return handleAuthAck(data, session)
	} else {
		return handleFrame(data, session)
	}

}
func handleAuthMessage(data []byte, session *session.Session) (Packet, byte, error) {
	prefix := data[0:2]

	packet := data[2:]

	// Decrypt the auth message using our private key
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// Deserialize the auth message
	var authMessage AuthMessage
	err = deserializePacket(decrypted, &authMessage)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to deserialize auth-message data: %w", err)
	}

	// Convert initiator's public key bytes to ECDSA public key
	initiatorPubKey, err := PubkeyToECDSA(authMessage.InitiatorPK)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to convert initiator public key: %w", err)
	}

	// Get the static shared secret using our private key and initiator's public key
	token, err := ecies.ImportECDSA(G.PRIVATE_KEY).GenerateShared(
		ecies.ImportECDSAPublic(initiatorPubKey),
		sskLen,
		sskLen,
	)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	// Verify signature (static-shared-secret ^ nonce)
	signedMsg := xor(token, authMessage.Nonce[:])
	recoveredPubKeyBytes, err := crypto.Ecrecover(signedMsg, authMessage.Signature[:])
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to recover public key from signature: %w", err)
	}

	// Convert the recovered public key bytes to ECDSA public key
	recoveredPubKey, err := crypto.UnmarshalPubkey(recoveredPubKeyBytes)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to unmarshal recovered public key: %w", err)
	}

	// Save the remote ephemeral public key to session
	session.SetRemoteEphemeralPublicKey(ecies.ImportECDSAPublic(recoveredPubKey))

	// Save nonces
	session.SetInitNonce(authMessage.Nonce[:])

	// Generate recipient nonce
	recNonce := make([]byte, shaLen)
	if _, err := rand.Read(recNonce); err != nil {
		return nil, 0x00, fmt.Errorf("failed to generate recipient nonce: %w", err)
	}
	session.SetRecNonce(recNonce)

	// Ephemeral Private Key
	ephemeralPrivateKey, err := GenerateRandomEphemeralPrivateKey()
	if err != nil {
		return nil, 0x00, err
	}
	session.SetEphemeralPrivateKey(ephemeralPrivateKey)

	// -----------------------
	// SECRETS generation is in callback

	// save to auth
	session.AddAuth(data)

	return authMessage, 0x01, nil
}

func handleAuthAck(data []byte, session *session.Session) (Packet, byte, error) {
	prefix := data[0:2]
	size := binary.BigEndian.Uint16(prefix)

	if size > 2048 {
		return nil, 0x00, fmt.Errorf("auth-ack message too big")
	}

	packet := data[2 : int(size)+2]
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// ---------
	var authAck AuthAck
	err = deserializePacket(decrypted, &authAck)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to deserialize auth-ack data: %w", err)
	}

	// Save Nonce
	session.SetRecNonce(authAck.Nonce[:])

	// Get ecies recipient ephemeral key and save it
	ephemeral_ecdsa_public_key, err := PubkeyToECDSA(authAck.RecipientEphemeralKey)
	if err != nil {
		return nil, 0x00, fmt.Errorf("error deriving public key from bytes: %v", err)
	}
	session.SetRemoteEphemeralPublicKey(ecies.ImportECDSAPublic(ephemeral_ecdsa_public_key))

	// -----------------------
	// STATE
	session.AddAuthAck(data)
	session.SetActive()

	// -----------------------
	// SECRETS

	err = GenerateSecrets(session)
	if err != nil {
		return nil, 0x00, fmt.Errorf("error generating auth-ack secrets")
	}

	return authAck, 0x02, nil
}

func handleFrame(data []byte, session *session.Session) (Packet, byte, error) {
	// Frame Header
	header := data[:32]

	// Verify header MAC.
	wantHeaderMAC := session.IngressMAC.ComputeHeader(header[:16])
	if !hmac.Equal(wantHeaderMAC, header[16:]) {
		return nil, 0x00, fmt.Errorf("incorrect header-mac")
	}

	// Decrypt the frame header to get the frame size.
	session.Dec.XORKeyStream(header[:16], header[:16])

	fsize := ReadUint24(header[:16])
	// Frame size rounded up to 16 byte boundary for padding.
	rsize := fsize
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}

	frame := data[32 : 32+int(rsize)]

	// Validate frame MAC.
	frameMAC := data[len(data)-16:]
	wantFrameMAC := session.IngressMAC.ComputeFrame(frame)
	if !hmac.Equal(wantFrameMAC, frameMAC) {
		return nil, 0x00, fmt.Errorf("incorrect frame-mac")
	}

	// Decrypt the frame data.
	session.Dec.XORKeyStream(frame, frame)

	real_decrypted_frame := frame[:fsize]

	code, frame_data, err := rlp.SplitUint64(real_decrypted_frame)
	if err != nil {
		return 0, 0x00, fmt.Errorf("invalid message code: %v", err)
	}

	// use snappy
	// [TODO] redo buffer stuff here
	if session.IsCompressionActive() {
		var actualSize int
		actualSize, err = snappy.DecodedLen(frame_data)
		if err != nil {
			return nil, 0x00, err
		}
		if actualSize > 2<<24 {
			return code, 0x00, fmt.Errorf("message too large")
		}
		nData, err := snappy.Decode(nil, frame_data)
		if err != nil {
			return nil, 0x00, err
		}
		frame_data = make([]byte, len(nData))
		copy(frame_data, nData)
	}

	var resolved_frame Packet

	// Disconnect was sent and was not RLP encoded
	// Parse that byte directly
	if code == 1 && len(frame_data) == 1 {
		resolved_frame = &FrameDisconnect{Reason: uint64(frame_data[0])}
		return resolved_frame, 0x03, nil
	}

	switch code {
	case 0:
		resolved_frame = &FrameHello{}
	case 1:
		resolved_frame = &FrameDisconnect{}
	case 2:
		resolved_frame = &FramePing{}
	case 3:
		resolved_frame = &FramePong{}
	case 16:
		resolved_frame = &Status{}
	default:
		return nil, 0x00, fmt.Errorf("unknown frame type: %d", code)
	}

	err = deserializePacket(frame_data, resolved_frame)
	if err != nil {
		return nil, 0x00, err
	}

	return resolved_frame, 0x03, nil
}

// ------------------------------------
// Deserializing

func deserializePacket(data []byte, v interface{}) error {
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(v)
	if err != nil {
		return fmt.Errorf("error deserializing: %v", err)
	}
	return nil
}
