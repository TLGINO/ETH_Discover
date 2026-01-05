package transport

import (
	"eth_discover/rlpx"

	G "eth_discover/global"
	"eth_discover/session"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/rs/zerolog/log"
)

func (tn *TransportNode) ExecAuth(m rlpx.Packet, session *session.Session) {
	auth := m.(rlpx.AuthMessage)
	log.Info().Str("component", "rlpx").Msg("received auth")

	initiatorPubKey, err := rlpx.PubkeyToECDSA(auth.InitiatorPK)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("failed to convert initiator public key")
		return
	}
	// -----------------------
	// Create Auth Ack
	authAckData, err := rlpx.CreateAuthAck(session, initiatorPubKey)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("failed to create auth-ack")
		return
	}

	// -----------------------
	// STATE

	session.AddAuthAck(authAckData)
	session.SetActive()

	// -----------------------
	// SECRETS

	err = rlpx.GenerateSecrets(session)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("error generating auth secrets")
		return
	}

	// -----------------------
	// Sending Auth-Ack back
	tn.SendTCP(session, authAckData)

	// -----------------------
	// Sending first Hello Frame
	helloFrame, err := rlpx.CreateFrameHello(session)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("error creating hello frame")
		return
	}
	tn.SendTCP(session, helloFrame)
}
func (tn *TransportNode) ExecAuthAck(m rlpx.Packet, session *session.Session) {
	// authAck := m.(rlpx.AuthAck)
	log.Info().Str("component", "rlpx").Msg("received authAck")
	// -----------------------
	// Sending first Hello Frame
	helloFrame, err := rlpx.CreateFrameHello(session)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("error creating hello frame")
		return
	}
	tn.SendTCP(session, helloFrame)

}

func (tn *TransportNode) ExecFrame(m rlpx.Packet, sess *session.Session) {
	f := m.(rlpx.FrameContent)

	switch frame := f.(type) {
	case *rlpx.FrameHello:
		log.Info().Str("component", "eth").Msgf("received hello frame %v", frame.String())

		// hello handshake completed
		// can send eth status
		status, err := rlpx.CreateStatusMessage(sess)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating status message")
			return
		}
		tn.SendTCP(sess, status)
		sess.SetBonded()
		sess.SetNodeID(frame.ClientID, frame.NodeID)

	case *rlpx.FrameDisconnect:
		ip, _ := sess.To()
		log.Info().Str("component", "eth").Msgf("received disconnect frame %v from %v", frame.String(), ip.String())

		// disconnect and cleanup
		tn.Disconnect(sess, 0)
		disc := f.(*rlpx.FrameDisconnect)
		tn.node.InsertNodeDisconnect(sess, disc)

	case *rlpx.FramePing:
		log.Info().Str("component", "eth").Msg("received ping frame")
		pong, err := rlpx.CreateFramePong(sess)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating pong message")
			return
		}
		tn.SendTCP(sess, pong)

	case *rlpx.FramePong:
		log.Info().Str("component", "eth").Msg("received pong frame")
	case *rlpx.Status:
		log.Info().Str("component", "eth").Msgf("received status frame %v", frame.String())

		// log it
		status := f.(*rlpx.Status)
		tn.node.InsertNodeStatus(sess, status)
		// Check if suitable based on our config
		if frame.NetworkID != G.CONFIG.NetworkID {
			// disconnect and cleanup
			tn.Disconnect(sess, 0x03)
			return
		}
		sess.SetBonded()
	case *rlpx.NewBlockHashes:
		log.Info().Str("component", "eth").Msgf("received newBlockHashes frame %v", frame.String())
	case *rlpx.Transactions:
		log.Info().Str("component", "eth").Msgf("received transaction frame %v", frame.String())

		transactions := f.(*rlpx.Transactions)
		// for _, tx := range transactions.Transactions {
		// 	tn.node.InsertTX(sess, tx, false)

		// }
		// Build a map of unseen transactions per peer
		peerTxMap := make(map[string][]*types.Transaction)

		for _, tx := range transactions.Transactions {
			tn.node.InsertTX(sess, tx, false)
			tn.AddTxHashSender(tx.Hash(), sess.GetID(), tx)

			sessionIDs := tn.GetTxHashSenders(tx.Hash())
			seen := make(map[string]struct{})
			for _, id := range sessionIDs {
				seen[id] = struct{}{}
			}

			// Build map of unseen transactions for each peer
			for _, peer := range tn.GetSessionManager().GetAllSessions() {
				if !peer.IsBonded() {
					continue
				}
				if peer == nil {
					continue
				}
				pid := peer.GetID()
				// don't send back to original sender or to peers that already sent us this tx
				if pid == sess.GetID() {
					continue
				}
				if _, ok := seen[pid]; ok {
					continue
				}

				// Add this transaction to the peer's unseen list
				peerTxMap[pid] = append(peerTxMap[pid], tx)
			}
		}

		// Send all unseen transactions for each peer in a single batch
		for pid, txs := range peerTxMap {
			// Find the peer by ID
			var peer *session.Session
			for _, p := range tn.GetSessionManager().GetAllSessions() {
				if p.GetID() == pid {
					peer = p
					break
				}
			}
			if peer == nil {
				continue
			}

			msg, err := rlpx.CreateTransactions(peer, txs)
			if err != nil {
				log.Err(err).Str("component", "eth").Msg("error creating Transactions")
				continue
			}

			tn.SendTCP(peer, msg)
			for _, t := range txs {
				tn.node.InsertTX(peer, t, true)
				tn.AddTxHashSender(t.Hash(), pid, t)
			}
		}

	case *rlpx.GetBlockHeaders:
		log.Info().Str("component", "eth").Msgf("received getBlockHeaders frame %v", frame.String())

		// Respond with empty headers (we don't store full block data)
		request := frame
		response, err := rlpx.CreateBlockHeaders(sess, request.RequestId, nil)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating BlockHeaders response")
			break
		}
		tn.SendTCP(sess, response)

	case *rlpx.GetBlockBodies:
		log.Info().Str("component", "eth").Msgf("received getBlockBodies frame %v", frame.String())

		// Respond with empty bodies (we don't store full block data)
		request := frame
		response, err := rlpx.CreateBlockBodies(sess, request.RequestID, nil)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating BlockBodies response")
			break
		}
		tn.SendTCP(sess, response)
	case *rlpx.BlockBodies:
		log.Info().Str("component", "eth").Msgf("received blockBodies frame %v", frame.String())
		// panic("3")
	case *rlpx.NewBlock:
		log.Info().Str("component", "eth").Msgf("received newBlock frame %v", frame.String())
	case *rlpx.NewPooledTransactionHashes:
		log.Info().Str("component", "eth").Msgf("received newPooledTransactionHashes frame %v", frame.String())

		// get the pooled transactions
		newPooledTransactionHashes := f.(*rlpx.NewPooledTransactionHashes)

		// Split hashes into chunks of 256
		const maxHashes = 256
		for i := 0; i < len(newPooledTransactionHashes.Hashes); i += maxHashes {
			end := i + maxHashes
			if end > len(newPooledTransactionHashes.Hashes) {
				end = len(newPooledTransactionHashes.Hashes)
			}

			request_id := rand.Uint64()
			getPooledTransactions, err := rlpx.CreateGetPooledTransactions(sess, request_id, newPooledTransactionHashes.Hashes[i:end])
			if err != nil {
				log.Err(err).Str("component", "eth").Msg("error creating getPooledTransactions message")
				continue
			}
			tn.SendTCP(sess, getPooledTransactions)
			tn.node.GetTracker().Add(request_id, 60*time.Second)

		}

	case *rlpx.GetPooledTransactions:
		log.Info().Str("component", "eth").Msgf("received getPooledTransactions frame %v", frame.String())

		// collect requested transactions
		request := frame
		txs := make([]*types.Transaction, 0, len(request.Hashes))
		for _, h := range request.Hashes {
			tx := tn.GetTransaction(h)
			if tx != nil {
				txs = append(txs, tx)
			}
		}

		// create and send pooledTransactions response
		pooledMsg, err := rlpx.CreatePooledTransactions(sess, request.RequestID, txs)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating pooledTransactions message")
			break
		}
		println("HERE SENDING TRANSACTION")
		tn.SendTCP(sess, pooledMsg)

	case *rlpx.PooledTransactions:
		log.Info().Str("component", "eth").Msgf("received pooledTransactions frame %v", frame.String())
		pooledTransactions := f.(*rlpx.PooledTransactions)
		found := tn.node.GetTracker().GetAndRemove(pooledTransactions.RequestID)
		// Save transactions to a file
		if found {
			println("Found my transactions!")

			// Build a map of unseen transactions per peer
			peerTxMap := make(map[string][]*types.Transaction)

			for _, tx := range pooledTransactions.Transactions {
				tn.node.InsertTX(sess, tx, false)
				tn.AddTxHashSender(tx.Hash(), sess.GetID(), tx)

				sessionIDs := tn.GetTxHashSenders(tx.Hash())
				seen := make(map[string]struct{})
				for _, id := range sessionIDs {
					seen[id] = struct{}{}
				}

				// Build map of unseen transactions for each peer
				for _, peer := range tn.GetSessionManager().GetAllSessions() {
					if !peer.IsBonded() {
						continue
					}
					if peer == nil {
						continue
					}
					pid := peer.GetID()
					// don't send back to original sender or to peers that already sent us this tx
					if pid == sess.GetID() {
						continue
					}
					if _, ok := seen[pid]; ok {
						continue
					}

					// Add this transaction to the peer's unseen list
					peerTxMap[pid] = append(peerTxMap[pid], tx)
				}
			}

			// Send all unseen transactions for each peer in a single batch
			for pid, txs := range peerTxMap {
				// Find the peer by ID
				var peer *session.Session
				for _, p := range tn.GetSessionManager().GetAllSessions() {
					if p.GetID() == pid {
						peer = p
						break
					}
				}
				if peer == nil {
					continue
				}

				msg, err := rlpx.CreateTransactions(peer, txs)
				if err != nil {
					log.Err(err).Str("component", "eth").Msg("error creating Transactions")
					continue
				}

				tn.SendTCP(peer, msg)
				for _, t := range txs {
					tn.node.InsertTX(peer, t, true)
					tn.AddTxHashSender(t.Hash(), pid, t)
				}
			}
		}
	default:
		log.Warn().Str("component", "eth").Msg("received unknown frame type")
	}
}
