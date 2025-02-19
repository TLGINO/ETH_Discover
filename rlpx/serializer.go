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
	"github.com/rs/zerolog/log"
)

func DeserializePacket(data []byte, session *session.Session, found bool) (Packet, byte, error) {
	// 3 cases
	// we have received an auth message
	// we have received an auth-ack message
	// we have received a frame

	if !found {
		log.Info().Msg("received auth message")
		return handleAuthMessage(data, session)
	} else if !session.IsActive() {
		log.Info().Msg("received auth-ack message")
		return handleAuthAck(data, session)
	} else {
		log.Info().Msg("received a frame")
		return handleFrame(data, session)
	}

}
func handleAuthMessage(data []byte, session *session.Session) (Packet, byte, error) {
	var p AuthPacket
	prefix := data[0:2]
	p.Size = binary.BigEndian.Uint16(prefix)

	packet := data[2:]

	// Decrypt the auth message using our private key
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// Deserialize the auth message
	authMessage, err := deserializeAuthMessage(decrypted)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to deserialize packet data: %w", err)
	}
	p.Body = authMessage
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

	return p, 0x01, nil
}

func handleAuthAck(data []byte, session *session.Session) (Packet, byte, error) {
	var p AuthPacket
	prefix := data[0:2]
	p.Size = binary.BigEndian.Uint16(prefix)

	if p.Size > 2048 {
		return nil, 0x00, fmt.Errorf("auth-ack message too big")
	}

	packet := data[2 : int(p.Size)+2]
	decrypted, err := ecies.ImportECDSA(G.PRIVATE_KEY).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to decrypt packet data: %w", err)
	}

	// ---------

	authAck, err := deserializeAuthAck(decrypted)
	if err != nil {
		return nil, 0x00, fmt.Errorf("failed to deserialize packet data: %w", err)
	}
	p.Body = authAck

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

	return p, 0x02, nil
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

	code, data, err := rlp.SplitUint64(real_decrypted_frame)
	if err != nil {
		return 0, 0x00, fmt.Errorf("invalid message code: %v", err)
	}
	fmt.Printf("\nCODE: %d\n\n", code)

	return nil, 0x03, nil
}

func deserializeAuthMessage(data []byte) (*AuthMessage, error) {
	var m AuthMessage
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing Auth: " + err.Error())
	}
	return &m, nil
}
func deserializeAuthAck(data []byte) (*AuthAck, error) {
	var m AuthAck
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing AuthAck: " + err.Error())
	}
	return &m, nil
}
func deserializeHello(data []byte) (*FrameHello, error) {
	var m FrameHello
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing FrameHello: " + err.Error())
	}
	return &m, nil
}
