package global

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

var (
	PRIVATE_KEY           *ecdsa.PrivateKey
	PUBLIC_KEY            *ecdsa.PublicKey
	COMPRESSED_PUBLIC_KEY [33]byte
	hasBeenCalled         bool
)

func CreatePK() {
	// can only call this once
	if hasBeenCalled {
		return
	}
	hasBeenCalled = true

	pk, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("error generating private key:", err)
		return
	}
	PRIVATE_KEY = pk
	PUBLIC_KEY = &pk.PublicKey
	COMPRESSED_PUBLIC_KEY = [33]byte(crypto.CompressPubkey(PUBLIC_KEY))
}
