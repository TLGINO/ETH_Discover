package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"

	"github.com/rs/zerolog/log"
)

func (tn *TransportNode) ExecAuth(m rlpx.Packet, session *session.Session) {
	auth := m.(rlpx.AuthMessage)
	log.Info().Msg("received auth")

	initiatorPubKey, err := rlpx.PubkeyToECDSA(auth.InitiatorPK)
	if err != nil {
		log.Err(err).Msg("failed to convert initiator public key")
		return
	}
	// -----------------------
	// Create Auth Ack
	authAckData, err := rlpx.CreateAuthAck(session, initiatorPubKey)
	if err != nil {
		log.Err(err).Msg("failed to create auth-ack")
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
		log.Err(err).Msg("error generating auth secrets")
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
	log.Info().Msg("received authAck")

	// -----------------------
	// Sending first Hello Frame

	tn.TestHello(session)
	session.SetCompressionActive() // if we send and receive a hello, use snappy
}

func (tn *TransportNode) ExecFrame(m rlpx.Packet, session *session.Session) {
	f := m.(rlpx.FrameContent)

	switch frame := f.(type) {
	case *rlpx.FrameHello:
		log.Info().Msg("received hello frame")
		session.SetCompressionActive() // if we send and receive a hello, use snappy
		println(frame.String())
	case *rlpx.FrameDisconnect:
		log.Info().Msg("received disconnect frame")
		println(frame.String())
	default:
		log.Warn().Msg("received unknown frame type")
	}
}
