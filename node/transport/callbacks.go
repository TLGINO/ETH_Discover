package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"

	"github.com/rs/zerolog/log"
)

func (tn *TransportNode) ExecAuth(m rlpx.Packet, session *session.Session) {
	authPacket := m.(rlpx.AuthPacket)
	auth := authPacket.Body.(*rlpx.AuthMessage)
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
}
func (tn *TransportNode) ExecAuthAck(m rlpx.Packet, session *session.Session) {
	// authAck := m.(rlpx.AuthPacket)
	log.Info().Msg("received authAck")
}

func (tn *TransportNode) ExecFrame(m rlpx.Packet, session *session.Session) {
	// switch frame := m.(type) {
	// case rlpx.FrameHello:
	// 	fmt.Printf("received hello frame\n")
	// case rlpx.FrameDisconnect:
	// 	fmt.Printf("received disconnect frame\n")
	// default:
	// 	log.Error().Msg("received unknown frame type")
	// }
}
