package transport

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/rs/zerolog/log"
)

func PublicKeyFromBytes(pubKeyBytes [64]byte) (*ecdsa.PublicKey, error) {
	// First, create the full 65-byte public key by adding the 0x04 prefix
	fullPubKey := make([]byte, 65)
	fullPubKey[0] = 0x04 // Uncompressed public key prefix
	copy(fullPubKey[1:], pubKeyBytes[:])

	// Parse the public key
	curve := secp256k1.S256() // Get the secp256k1 curve
	x := new(big.Int).SetBytes(pubKeyBytes[:32])
	y := new(big.Int).SetBytes(pubKeyBytes[32:])

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("public key point is not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (tn *TransportNode) StartHandShake() {
	allENodeTuples := tn.node.GetAllENodes()
	var filteredENodes []*interfaces.ENode
	for _, enodeTuple := range allENodeTuples {
		if enodeTuple.State == interfaces.BondedENode {
			filteredENodes = append(filteredENodes, &enodeTuple.Enode)
		}
	}

	defer func() {
		for _, eNode := range filteredENodes {
			tn.node.TestAndSetEnode(eNode, interfaces.BondedENode, interfaces.InitiatedTransport)
		}
	}()

	for _, eNode := range filteredENodes {
		sessionID := fmt.Sprintf("%s:%d", eNode.IP.String(), eNode.TCP)
		session := tn.sessionManager.AddSession(sessionID, eNode.IP, eNode.TCP)
		session.SetInitiator() // Set ourselves as the initiator

		recipientPK, err := rlpx.PubkeyToECDSA(eNode.ID)
		if err != nil {
			log.Err(err).Str("component", "rlpx").Msg("error converting key")
			return
		}
		authMessage, err := rlpx.CreateAuthMessage(session, recipientPK)
		if err != nil {
			log.Err(err).Str("component", "rlpx").Msg("error creating auth message")
			return
		}

		tn.SendTCP(session, authMessage)
	}
}

func (tn *TransportNode) TestBlock() {
	sessions := tn.sessionManager.GetAllSessions()
	for _, session := range sessions {
		if session.IsBonded() {
			// can start requesting blocks
			getBlockFrame, err := rlpx.CreateFrameGetBlockBodies(session)
			if err != nil {
				log.Err(err).Str("component", "rlpx").Msg("error creating getBlockBodies frame")
				return
			}
			// getBlockHeadersFrame, err := rlpx.CreateFrameGetBlockHeaders(session)
			// if err != nil {
			// 	log.Err(err).Str("component", "rlpx").Msg("error creating getBlockHeaders frame")
			// 	return
			// }
			tn.SendTCP(session, getBlockFrame)
		}
	}
}

func (tn *TransportNode) SendPing() {
	sessions := tn.sessionManager.GetAllSessions()
	for _, session := range sessions {
		if session.IsBonded() {
			// can start requesting blocks
			ping, err := rlpx.CreateFramePing(session)
			if err != nil {
				log.Err(err).Str("component", "rlpx").Msg("error creating framePing frame")
				return
			}

			tn.SendTCP(session, ping)
		}
	}
}
func (tn *TransportNode) Disconnect(session *session.Session, reason uint64) {
	// Send disconnect then close connection
	disconnect, err := rlpx.CreateFrameDisconnect(session, reason)
	if err != nil {
		log.Err(err).Str("component", "eth").Msg("error creating disconnect message")
		return
	}
	tn.SendTCP(session, disconnect)
	// sleep 2 seconds, as per protocol request
	time.Sleep(2 * time.Second)

	tn.tcp.Close(session)
}

// RelayBlockToPeers sends a NewBlock message to all bonded peers.
func (tn *TransportNode) RelayBlockToPeers(block *types.Block, td *big.Int) {
	if block == nil {
		return
	}

	sessions := tn.sessionManager.GetAllSessions()
	relayCount := 0
	
	for _, session := range sessions {
		if !session.IsBonded() {
			continue
		}

		newBlockMsg, err := rlpx.CreateNewBlock(session, block, td)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating NewBlock message")
			continue
		}

		tn.SendTCP(session, newBlockMsg)
		relayCount++
	}

	if relayCount > 0 {
		log.Info().Str("component", "eth").
			Uint64("block_number", block.NumberU64()).
			Str("block_hash", block.Hash().Hex()).
			Int("peers", relayCount).
			Msg("Relayed block to peers")
	}
}

func (tn *TransportNode) GetAndSendPendingTransactionFromAlchemy(ctx context.Context) {
	wsURL := "wss://eth-mainnet.g.alchemy.com/v2/hNDILvs5J8QZTv8t9KJx_LK_AE7hgFR6"

	for { // Outer loop to handle disconnections and attempt reconnection
		log.Info().Msg("Attempting to connect to Alchemy for pending transactions...")

		wsClient, err := rpc.DialContext(ctx, wsURL)
		if err != nil {
			log.Error().Err(err).Msg("Failed to dial WebSocket, retrying in 5 seconds")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		// --- Subscription Setup ---
		txCh := make(chan *types.Transaction)
		params := []interface{}{"alchemy_pendingTransactions", map[string]interface{}{"hashesOnly": false}}
		sub, err := wsClient.Subscribe(ctx, "eth", txCh, params...)
		if err != nil {
			log.Error().Err(err).Msg("Failed to subscribe, closing client and retrying")
			wsClient.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		// --- Listening Loop ---
		log.Info().Msg("Successfully subscribed to Alchemy pending transactions.")

		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("Context cancelled, unsubscribing from Alchemy.")
				sub.Unsubscribe()
				wsClient.Close()
				return

			case err := <-sub.Err():
				// The subscription/connection is broken, break the inner loop
				// and the outer loop will attempt to reconnect.
				log.Error().Err(err).Msg("Subscription error, attempting reconnection...")
				wsClient.Close()
				goto Reconnect

			case tx := <-txCh:
				// Received a pending transaction
				txHash := tx.Hash() // Get the transaction hash
				var txHashArray [32]byte
				copy(txHashArray[:], txHash.Bytes()) // Convert common.Hash to [32]byte

				// The 'from' address is not directly available in types.Transaction for
				// pending transactions without calling tx.AsMessage(signer) which requires a Signer.
				// However, the prompt is about using AddTxHashSender with "alchemy" as the sender string.
				sender := "alchemy"

				// Log and call the user's function
				// fmt.Printf("Received pending transaction: %s\n", txHash.Hex())
				tn.AddTxHashSender(txHashArray, sender, tx)

				// NOTE: The "do not do the sending part for now" instruction is followed.
				// Add your sending logic here later if needed.
				// iterate all known sessions and send the announcement to those not in seen
				// this is duplicated code from callback
				// not good i know
				sessionIDs := tn.GetTxHashSenders(txHash)
				seen := make(map[string]struct{})
				for _, id := range sessionIDs {
					seen[id] = struct{}{}
				}
				for _, peer := range tn.GetSessionManager().GetAllSessions() {
					// println("HERE SENDING TX TO OTHERS")
					if !peer.IsBonded() {
						continue
					}
					if peer == nil {
						continue
					}
					println("HERE SENDING TX TO OTHERS 1")
					pid := peer.GetID()
					// don't send back to original sender or to peers that already sent us this tx
					// if pid == session.GetID() {
					// 	continue
					// }
					if _, ok := seen[pid]; ok {
						continue
					}
					println("HERE SENDING TX TO OTHERS 2")

					// prepare single-element slices for the NewPooledTransactionHashes message
					types := []byte{tx.Type()}
					sizes := []uint32{uint32(tx.Size())}
					h := tx.Hash()
					var hArr [32]byte
					copy(hArr[:], h[:])
					hashes := [][32]byte{hArr}
					log.Info().Str("component", "eth").Msgf("pid=%s types=%v sizes=%v hashes=%v", pid, types, sizes, hashes)
					msg, err := rlpx.CreateNewPooledTransactionHashes(peer, types, sizes, hashes)
					if err != nil {
						log.Err(err).Str("component", "eth").Msg("error creating NewPooledTransactionHashes")
						continue
					}

					println("HERE SENDING TX TO OTHERS 3")

					tn.SendTCP(peer, msg)
					tn.node.InsertTX(peer, tx, true)
					tn.AddTxHashSender(tx.Hash(), pid, tx)
				}

				// case <-time.After(5 * time.Minute):
				// 	// Example of how to handle a timeout or stopping condition (optional)
				// 	fmt.Println("5 minutes passed, stopping transaction gathering.")
				// 	return
			}
		}
	Reconnect:
		// Wait a moment before the outer loop tries to connect again
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
			// Outer loop continues (for {}) to the next connection attempt
		}
	}
}
