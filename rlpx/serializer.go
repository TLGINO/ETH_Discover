package rlpx

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"io"

	"encoding/binary"
	G "eth_discover/global"
	"eth_discover/session"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

func DeserializePacket(conn io.Reader, session *session.Session, found bool) (Packet, byte, error) {
	if !found {
		packet, err := handleAuthMessage(conn, session)
		return packet, 0x01, err
	} else if !session.IsActive() {
		packet, err := handleAuthAck(conn, session)
		return packet, 0x02, err
	} else {
		packet, err := handleFrame(conn, session)
		return packet, 0x03, err
	}

}
func handleAuthMessage(conn io.Reader, session *session.Session) (Packet, error) {
	session.Rbuf.Reset()

	// Frame Header
	prefix, err := session.Rbuf.Read(conn, 2)
	if err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint16(prefix)
	packet, err := session.Rbuf.Read(conn, int(size))
	if err != nil {
		return nil, err
	}

	// Decrypt the auth message using our private key
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// Deserialize the auth message
	var authMessage AuthMessage
	err = deserializePacket(decrypted, &authMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize auth-message data: %w", err)
	}

	// Convert initiator's public key bytes to ECDSA public key
	initiatorPubKey, err := PubkeyToECDSA(authMessage.InitiatorPK)
	if err != nil {
		return nil, fmt.Errorf("failed to convert initiator public key: %w", err)
	}

	// Get the static shared secret using our private key and initiator's public key
	token, err := ecies.ImportECDSA(G.PRIVATE_KEY).GenerateShared(
		ecies.ImportECDSAPublic(initiatorPubKey),
		sskLen,
		sskLen,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared secret: %w", err)
	}

	// Verify signature (static-shared-secret ^ nonce)
	signedMsg := xor(token, authMessage.Nonce[:])
	recoveredPubKeyBytes, err := crypto.Ecrecover(signedMsg, authMessage.Signature[:])
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key from signature: %w", err)
	}

	// Convert the recovered public key bytes to ECDSA public key
	recoveredPubKey, err := crypto.UnmarshalPubkey(recoveredPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recovered public key: %w", err)
	}

	// Save the remote ephemeral public key to session
	session.SetRemoteEphemeralPublicKey(ecies.ImportECDSAPublic(recoveredPubKey))

	// Save nonces
	session.SetInitNonce(authMessage.Nonce[:])

	// Generate recipient nonce
	recNonce := make([]byte, shaLen)
	if _, err := rand.Read(recNonce); err != nil {
		return nil, fmt.Errorf("failed to generate recipient nonce: %w", err)
	}
	session.SetRecNonce(recNonce)

	// Ephemeral Private Key
	ephemeralPrivateKey, err := GenerateRandomEphemeralPrivateKey()
	if err != nil {
		return nil, err
	}
	session.SetEphemeralPrivateKey(ephemeralPrivateKey)

	// -----------------------
	// SECRETS generation is in callback

	// save to auth
	session.AddAuth(append(prefix, packet...))

	return authMessage, nil
}

func handleAuthAck(conn io.Reader, session *session.Session) (Packet, error) {
	// prefix := data[0:2]
	prefix, err := session.Rbuf.Read(conn, 2)
	if err != nil {
		return nil, err
	}

	// prefix := data[0:2]
	size := binary.BigEndian.Uint16(prefix)

	if size > 2048 {
		return nil, fmt.Errorf("auth-ack message too big")
	}
	packet, err := session.Rbuf.Read(conn, int(size))
	if err != nil {
		return nil, err
	}

	// packet := data[2 : int(size)+2]
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// ---------
	var authAck AuthAck
	err = deserializePacket(decrypted, &authAck)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize auth-ack data: %w", err)
	}

	// Save Nonce
	session.SetRecNonce(authAck.Nonce[:])

	// Get ecies recipient ephemeral key and save it
	ephemeral_ecdsa_public_key, err := PubkeyToECDSA(authAck.RecipientEphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("error deriving public key from bytes: %v", err)
	}
	session.SetRemoteEphemeralPublicKey(ecies.ImportECDSAPublic(ephemeral_ecdsa_public_key))

	// -----------------------
	// STATE
	// session.AddAuthAck(data)
	session.AddAuthAck(append(prefix, packet...))
	session.SetActive()

	// -----------------------
	// SECRETS

	err = GenerateSecrets(session)
	if err != nil {
		return nil, fmt.Errorf("error generating auth-ack secrets")
	}

	return authAck, nil
}

func handleFrame(conn io.Reader, session *session.Session) (Packet, error) {
	session.Rbuf.Reset()

	// fmt.Printf("Frame data: %x\n", data)
	// fmt.Printf("LEN: %d\n", len(data))
	// Frame Header
	header, err := session.Rbuf.Read(conn, 32)
	if err != nil {
		return nil, err
	}

	// Verify header MAC.
	wantHeaderMAC := session.IngressMAC.ComputeHeader(header[:16])

	if !hmac.Equal(wantHeaderMAC, header[16:]) {
		return nil, fmt.Errorf("incorrect header-mac")
	}

	// Decrypt the frame header to get the frame size.
	session.Dec.XORKeyStream(header[:16], header[:16])

	fsize := ReadUint24(header[:16])

	// Frame size rounded up to 16 byte boundary for padding.
	rsize := fsize
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}

	//

	frame, err := session.Rbuf.Read(conn, int(rsize))
	if err != nil {
		return nil, err
	}

	// Validate frame MAC.
	frameMAC, err := session.Rbuf.Read(conn, 16)
	if err != nil {
		return nil, err
	}

	wantFrameMAC := session.IngressMAC.ComputeFrame(frame)
	if !hmac.Equal(wantFrameMAC, frameMAC) {
		return nil, fmt.Errorf("incorrect frame-mac")
	}

	// Decrypt the frame data.
	session.Dec.XORKeyStream(frame, frame)

	real_decrypted_frame := frame[:fsize]

	code, frame_data, err := rlp.SplitUint64(real_decrypted_frame)
	if err != nil {
		return nil, fmt.Errorf("invalid message code: %v", err)
	}

	var resolved_frame Packet

	// Disconnect was sent and was not RLP encoded
	// It may or may not be snappy encoded
	// Try to decode normally
	if code == 1 {
		resolved_frame = &FrameDisconnect{}
		err = deserializePacket(frame_data, resolved_frame)
		if err == nil {
			return resolved_frame, nil
		}
	}
	// use snappy
	// [TODO] redo buffer stuff here
	if code != 0 {
		var actualSize int
		actualSize, err = snappy.DecodedLen(frame_data)
		if err != nil {
			return nil, err
		}
		if actualSize > 2<<24 {
			return nil, fmt.Errorf("message too large")
		}

		nData, err := snappy.Decode(nil, frame_data)
		if err != nil {
			return nil, err
		}
		frame_data = make([]byte, len(nData))
		copy(frame_data, nData)
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
	case 18:
		resolved_frame = &Transactions{}
	case 19:
		resolved_frame = &GetBlockHeaders{}
	case 21:
		resolved_frame = &GetBlockBodies{}
	case 22:
		resolved_frame = &BlockBodies{}
	case 23:
		resolved_frame = &NewBlock{}
	case 24:
		resolved_frame = &NewPooledTransactionHashes{}
	case 25:
		resolved_frame = &GetPooledTransactions{}
	case 26:
		resolved_frame = &PooledTransactions{}
	default:
		return nil, fmt.Errorf("unknown frame type: %d", code)
	}

	err = deserializePacket(frame_data, resolved_frame)
	if err != nil {
		return nil, err
	}

	return resolved_frame, nil
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
