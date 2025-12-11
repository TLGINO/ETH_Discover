package global

import (
	"context"
	"crypto/ecdsa"
	"eth_discover/interfaces"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
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

	// --- Block Tracker State ---
	latestBlockData CachedBlock
	blockMu         sync.RWMutex
)

// CachedBlock holds the minimal data you need for Status messages
type CachedBlock struct {
	Hash   common.Hash
	Number uint64
}

// GetLatestBlock returns the currently known tip of the chain.
// It reads from memory (mutex) and does NOT make a network call.
func GetLatestBlock() CachedBlock {
	blockMu.RLock()
	defer blockMu.RUnlock()
	return latestBlockData
}

// StartBlockListener connects to Alchemy via WebSocket and updates the
// latestBlockData variable in the background automatically.
func StartBlockListener(wsURL string) {
	go func() {
		// Keep trying to reconnect if connection drops
		for {
			runListener(wsURL)
			log.Warn().Msg("Block listener disconnected, reconnecting in 5s...")
			time.Sleep(5 * time.Second)
		}
	}()
}

func runListener(wsURL string) {
	ctx := context.Background()
	client, err := rpc.DialWebsocket(ctx, wsURL, "")
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to Alchemy WS")
		return
	}
	defer client.Close()

	// Define the subscription channel
	headers := make(chan map[string]interface{})
	sub, err := client.EthSubscribe(ctx, headers, "newHeads")
	if err != nil {
		log.Error().Err(err).Msg("Failed to subscribe to newHeads")
		return
	}

	log.Info().Msg("Started background block listener via WebSocket")

	for {
		select {
		case err := <-sub.Err():
			log.Error().Err(err).Msg("Subscription error")
			return
		case header := <-headers:
			// Parse the raw JSON-RPC result
			if hashStr, ok := header["hash"].(string); ok {
				blockMu.Lock()
				latestBlockData.Hash = common.HexToHash(hashStr)

				// Handle Block Number (can be hex string)
				if numStr, ok := header["number"].(string); ok {
					// Remove 0x and decode
					var num uint64
					// Geth hex util or fmt.Sscanf is useful here, simpler to use HexToBig usually
					// but here is a quick lightweight parse:
					if _, err := fmt.Sscanf(numStr, "0x%x", &num); err == nil {
						latestBlockData.Number = num
					}
				}
				blockMu.Unlock()

				// Optional: Debug log
				// log.Debug().Str("hash", hashStr).Msg("Updated latest block cache")
			}
		}
	}
}

func CreatePK() {
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
