package transport

import (
	"eth_discover/rlpx"

	G "eth_discover/global"
	"eth_discover/session"
	"math/rand"
	"time"

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

func (tn *TransportNode) ExecFrame(m rlpx.Packet, session *session.Session) {
	f := m.(rlpx.FrameContent)

	switch frame := f.(type) {
	case *rlpx.FrameHello:
		log.Info().Str("component", "eth").Msgf("received hello frame %v", frame.String())

		// hello handshake completed
		// can send eth status
		status, err := rlpx.CreateStatusMessage(session)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating status message")
			return
		}
		tn.SendTCP(session, status)
		session.SetBonded()
		session.SetNodeID(frame.ClientID, frame.NodeID)

	case *rlpx.FrameDisconnect:
		ip, _ := session.To()
		log.Info().Str("component", "eth").Msgf("received disconnect frame %v from %v", frame.String(), ip.String())

		// disconnect and cleanup
		tn.Disconnect(session, 0)
		disc := f.(*rlpx.FrameDisconnect)
		tn.node.InsertNodeDisconnect(session, disc)

	case *rlpx.FramePing:
		log.Info().Str("component", "eth").Msg("received ping frame")
		pong, err := rlpx.CreateFramePong(session)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating pong message")
			return
		}
		tn.SendTCP(session, pong)

	case *rlpx.FramePong:
		log.Info().Str("component", "eth").Msg("received pong frame")
	case *rlpx.Status:
		log.Info().Str("component", "eth").Msgf("received status frame %v", frame.String())

		// log it
		status := f.(*rlpx.Status)
		tn.node.InsertNodeStatus(session, status)
		// Check if suitable based on our config
		if frame.NetworkID != G.CONFIG.NetworkID {
			// disconnect and cleanup
			tn.Disconnect(session, 0x03)
			return
		}
		session.SetBonded()
	case *rlpx.Transactions:
		log.Info().Str("component", "eth").Msgf("received transaction frame %v", frame.String())

		transactions := f.(*rlpx.Transactions)
		for _, tx := range transactions.Transactions {
			tn.node.InsertTX(session, tx)
		}

	case *rlpx.GetBlockHeaders:
		log.Info().Str("component", "eth").Msgf("received getBlockHeaders frame %v", frame.String())
		// panic("1")
	case *rlpx.GetBlockBodies:
		log.Info().Str("component", "eth").Msgf("received getBlockBodies frame %v", frame.String())
		// panic("2")
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
			getPooledTransactions, err := rlpx.CreateGetPooledTransactions(session, request_id, newPooledTransactionHashes.Hashes[i:end])
			if err != nil {
				log.Err(err).Str("component", "eth").Msg("error creating getPooledTransactions message")
				continue
			}
			tn.SendTCP(session, getPooledTransactions)
			tn.node.GetTracker().Add(request_id, 60*time.Second)
		}

	case *rlpx.GetPooledTransactions:
		log.Info().Str("component", "eth").Msgf("received getPooledTransactions frame %v", frame.String())
		// panic("4")
	case *rlpx.PooledTransactions:
		log.Info().Str("component", "eth").Msgf("received pooledTransactions frame %v", frame.String())
		pooledTransactions := f.(*rlpx.PooledTransactions)
		found := tn.node.GetTracker().GetAndRemove(pooledTransactions.RequestID)
		// Save transactions to a file
		if found {
			println("Found my transactions!")
			for _, tx := range pooledTransactions.Transactions {
				tn.node.InsertTX(session, tx)
			}
		}
	default:
		log.Warn().Str("component", "eth").Msg("received unknown frame type")
	}
}
