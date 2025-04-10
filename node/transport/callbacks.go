package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"

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
	ip, port := session.To()
	tn.SendTCP(ip, port, authAckData)

	// -----------------------
	// Sending first Hello Frame

	tn.TestHello(session)
	session.SetCompressionActive() // if we send and receive a hello, use snappy
}
func (tn *TransportNode) ExecAuthAck(m rlpx.Packet, session *session.Session) {
	// authAck := m.(rlpx.AuthAck)
	log.Info().Str("component", "rlpx").Msg("received authAck")

	// -----------------------
	// Sending first Hello Frame

	tn.TestHello(session)
	session.SetCompressionActive() // if we send and receive a hello, use snappy
	if session.IsCompressionActive() {
		// hello handshake completed
		// can send eth status
		status, err := rlpx.CreateStatusMessage(session)
		if err != nil {
			log.Err(err).Str("component", "eth").Msg("error creating status message")
			return
		}
		ip, port := session.To()
		tn.SendTCP(ip, port, status)
		session.SetBonded()
	}
}

func (tn *TransportNode) ExecFrame(m rlpx.Packet, session *session.Session) {
	f := m.(rlpx.FrameContent)

	switch frame := f.(type) {
	case *rlpx.FrameHello:
		log.Info().Str("component", "eth").Msgf("received hello frame %v", frame.String())

		// if we send and receive a hello, use snappy
		session.SetCompressionActive()

		if session.IsCompressionActive() {
			// hello handshake completed
			// can send eth status
			status, err := rlpx.CreateStatusMessage(session)
			if err != nil {
				log.Err(err).Str("component", "eth").Msg("error creating status message")
				return
			}
			ip, port := session.To()
			tn.SendTCP(ip, port, status)
			session.SetBonded()
		}

	case *rlpx.FrameDisconnect:
		log.Info().Str("component", "eth").Msgf("received disconnect frame %v", frame.String())

		// Remove this session
		ip, _ := session.To()
		tn.sessionManager.RemoveSession(ip.String())
	case *rlpx.FramePing:
		log.Info().Str("component", "eth").Msg("received ping frame")
	case *rlpx.FramePong:
		log.Info().Str("component", "eth").Msg("received pong frame")
	case *rlpx.Status:
		log.Info().Str("component", "eth").Msgf("received status frame %v", frame.String())
		session.SetBonded()
	case *rlpx.GetBlockHeaders:
		log.Info().Str("component", "eth").Msgf("received getBlockHeaders frame %v", frame.String())
	case *rlpx.GetBlockBodies:
		log.Info().Str("component", "eth").Msgf("received getBlockBodies frame %v", frame.String())
	case *rlpx.BlockBodies:
		println("\n\n RECEIVED BLOCK DATA\n\n")
		log.Info().Str("component", "eth").Msgf("received blockBodies frame %v", frame.String())
		panic("AHH")
	default:
		log.Warn().Str("component", "eth").Msg("received unknown frame type")
	}
}
