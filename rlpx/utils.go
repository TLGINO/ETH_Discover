package rlpx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	sess "eth_discover/session"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

//
// ------------------------------------
// Helpers
//

func PubkeyToECDSA(pub [64]byte) (*ecdsa.PublicKey, error) {
	x := new(big.Int).SetBytes(pub[:32])
	y := new(big.Int).SetBytes(pub[32:])

	curve := secp256k1.S256()

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on curve")
	}

	publicKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}

func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}
func GenerateRandomEphemeralPrivateKey() (*ecies.PrivateKey, error) {
	randomPrivKey, err := ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}
	return randomPrivKey, err
}

func GenerateSecrets(session *sess.Session) error {
	// Once Secrets have been generated, can cleanup some session data
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

// EncodeRLP is a specialized encoder for HashOrNumber to encode only one of the
// two contained union fields.
func (hn *HashOrNumber) EncodeRLP(w io.Writer) error {
	if hn.Hash == (common.Hash{}) {
		return rlp.Encode(w, hn.Number)
	}
	if hn.Number != 0 {
		return fmt.Errorf("both origin hash (%x) and number (%d) provided", hn.Hash, hn.Number)
	}
	return rlp.Encode(w, hn.Hash)
}

// DecodeRLP is a specialized decoder for HashOrNumber to decode the contents
// into either a block hash or a block number.
func (hn *HashOrNumber) DecodeRLP(s *rlp.Stream) error {
	_, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case size == 32:
		hn.Number = 0
		return s.Decode(&hn.Hash)
	case size <= 8:
		hn.Hash = common.Hash{}
		return s.Decode(&hn.Number)
	default:
		return fmt.Errorf("invalid input size %d for origin", size)
	}
}

func HexToBytes(hash string) ([]byte, error) {
	if len(hash)%2 != 0 {
		return nil, fmt.Errorf("invalid hash length")
	}
	bytes := make([]byte, len(hash)/2)
	for i := 0; i < len(bytes); i++ {
		var err error
		bytes[i], err = hexToByte(hash[i*2], hash[i*2+1])
		if err != nil {
			return nil, err
		}
	}
	return bytes, nil
}

func hexToByte(high, low byte) (byte, error) {
	h, err := fromHexChar(high)
	if err != nil {
		return 0, err
	}
	l, err := fromHexChar(low)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func fromHexChar(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character: %c", c)
	}
}
