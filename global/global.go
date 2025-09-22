package global

import (
	"crypto/ecdsa"
	"eth_discover/interfaces"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
)

var (
	// Keys
	PRIVATE_KEY           *ecdsa.PrivateKey
	PUBLIC_KEY            *ecdsa.PublicKey
	COMPRESSED_PUBLIC_KEY [33]byte
	hasBeenCalled         bool
	// Config
	CONFIG              *interfaces.Config
	hasBeenCalledConfig bool
)

func CreatePK() {
	// can only call this once
	if hasBeenCalled {
		return
	}
	hasBeenCalled = true

	pk, err := crypto.GenerateKey()
	if err != nil {
		log.Error().Err(err).Msg("error generating private key")
		return
	}
	PRIVATE_KEY = pk
	PUBLIC_KEY = &pk.PublicKey
	COMPRESSED_PUBLIC_KEY = [33]byte(crypto.CompressPubkey(PUBLIC_KEY))
}

func SetPK(pk *ecdsa.PrivateKey) {
	// can only call this once
	if hasBeenCalled {
		return
	}
	hasBeenCalled = true

	PRIVATE_KEY = pk
	PUBLIC_KEY = &pk.PublicKey
	COMPRESSED_PUBLIC_KEY = [33]byte(crypto.CompressPubkey(PUBLIC_KEY))
}

func SetConfig(config *interfaces.Config) {
	if hasBeenCalledConfig {
		return
	}
	hasBeenCalledConfig = true
	CONFIG = config
}
