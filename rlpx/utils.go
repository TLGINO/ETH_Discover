package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	sess "eth_discover/session"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/sha3"
)

func GenerateRandomEphemeralPrivateKey() (*ecies.PrivateKey, error) {
	randomPrivKey, err := ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}
	return randomPrivKey, err
}

func GenerateSecrets(session *sess.Session) error {
	// [TODO] defer cleanup session
	defer session.Cleanup()

	// -----------------------
	// GENERAL SECRETES

	// ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
	ephemeralKey, err := session.GetEphemeralPrivateKey().GenerateShared(session.GetRemoteEphemeralPublicKey(), sskLen, sskLen)
	if err != nil {
		return fmt.Errorf("error generating ephemeral-key: %v", err)
	}

	// shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
	// Get Nonces
	initNonce, recNonce := session.GetNonces()
	if len(initNonce) == 0 || len(recNonce) == 0 {
		return fmt.Errorf("invalid nonce sizes, initNonce: %d, recNonce: %d", len(initNonce), len(recNonce))
	}
	sharedSecret := crypto.Keccak256(ephemeralKey, crypto.Keccak256(recNonce, initNonce))

	// aes-secret = keccak256(ephemeral-key || shared-secret)
	aesSecret := crypto.Keccak256(ephemeralKey, sharedSecret)

	// mac-secret = keccak256(ephemeral-key || aes-secret)
	macSecret := crypto.Keccak256(ephemeralKey, aesSecret)

	// Encryption
	encc, err := aes.NewCipher(aesSecret)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	iv := make([]byte, encc.BlockSize())

	session.Enc = cipher.NewCTR(encc, iv)
	session.Dec = cipher.NewCTR(encc, iv)

	// -----------------------
	// MAC SECRETS

	macc, err := aes.NewCipher(macSecret)
	if err != nil {
		return fmt.Errorf("invalid MAC secret: %v", err)
	}

	// Get Auth messages
	auth, auth_ack := session.GetAuthStates()
	if len(auth) == 0 || len(auth_ack) == 0 {
		return fmt.Errorf("invalid auth sizes, auth: %d, auth-ack: %d", len(auth), len(auth_ack))
	}

	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xor(macSecret, recNonce))
	mac1.Write(auth)
	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xor(macSecret, initNonce))
	mac2.Write(auth_ack)

	if session.IsInitiator() {
		session.EgressMAC = sess.NewHashMAC(macc, mac1)
		session.IngressMAC = sess.NewHashMAC(macc, mac2)
	} else {
		session.EgressMAC = sess.NewHashMAC(macc, mac2)
		session.IngressMAC = sess.NewHashMAC(macc, mac1)
	}
	return nil
}

func ReadUint24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func PutUint24(v uint32) [3]byte {
	var b [3]byte
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
	return b
}
