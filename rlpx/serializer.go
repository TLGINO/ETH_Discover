package rlpx

import (
	"bytes"
	"crypto/ecdsa"

	"encoding/binary"
	G "eth_discover/global"
	"eth_discover/session"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// DeserializePacket deserializes a raw packet into a Packet struct
func DeserializeAuthPacket(data []byte, session *session.Session) (*AuthPacket, error) {
	var p AuthPacket
	prefix := data[0:2]
	p.Size = binary.BigEndian.Uint16(prefix)

	packet := data[2:] // Changed from data[3:]

	println("p.Size: ", p.Size, "dataSize: ", len(data), "packet:", len(packet))

	var privateKey ecdsa.PrivateKey
	privateKey = *G.PRIVATE_KEY

	decrypted, err := ecies.ImportECDSA(&privateKey).Decrypt(packet, nil, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt packet data: %w", err)
	}
	if session == nil {
		authBody, err := deserializeAuthBody(decrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize packet data: %w", err)
		}
		p.Body = authBody
		// [TODO] send authAck here
	} else {
		authAck, err := deserializeAuthAck(decrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize packet data: %w", err)
		}
		p.Body = authAck
		println("HEREEEE GOOOOOD", authAck.String())

		// Save Nonce
		session.RecipientNonce = authAck.Nonce[:]

		// Get ecies recipient ephemeral key and save it
		ephemeral_ecdsa_public_key, err := PubkeyToECDSA(authAck.RecipientEphemeralKey)
		if err != nil {
			return nil, fmt.Errorf("error deriving public key from bytes: %v", err)
		}
		session.EphemeralPrivateKey_2 = ecies.ImportECDSAPublic(ephemeral_ecdsa_public_key)

		// Generate ephemeral key and save it

		ephemeralKey, err := session.EphemeralPrivateKey_1.GenerateShared(session.EphemeralPrivateKey_2, sskLen, sskLen)
		if err != nil {
			return nil, fmt.Errorf("error generating ephemeral secret: %v", err)
		}

		// Generate shared secret and save it
		sharedSecret := crypto.Keccak256(ephemeralKey, crypto.Keccak256(session.RecipientNonce, session.InitiatorNonce))
		session.SharedSecret = [32]byte(sharedSecret)

		// Generate AES secret and save it
		aesSecret := crypto.Keccak256(ephemeralKey, sharedSecret)
		session.AESSecret = [32]byte(aesSecret)

		// Generate MAC secret and save it
		macSecret := crypto.Keccak256(ephemeralKey, aesSecret)
		session.MACSecret = [32]byte(macSecret)

		// Generate Ingress and Egress MAC

		mac1 := sha3.NewLegacyKeccak256()
		mac1.Write(xor(macSecret, session.RecipientNonce))
		mac1.Write(session.AuthSent)
		mac2 := sha3.NewLegacyKeccak256()
		mac2.Write(xor(macSecret, session.InitiatorNonce))
		mac2.Write(session.AuthSent)
		if session.IsInitiator {
			session.EgressMac, session.IngressMac = mac1, mac2
		} else {
			session.EgressMac, session.IngressMac = mac2, mac1
		}

		println("\n\n\nMADE IT TO THE ENDDDDDDD\n\n\n")
	}

	return &p, nil
}

func deserializeAuthBody(data []byte) (*AuthBody, error) {
	var m AuthBody
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing AuthBody: " + err.Error())
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
