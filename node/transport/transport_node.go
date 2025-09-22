package transport

import (
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"eth_discover/session"
	"time"

	"github.com/rs/zerolog/log"
)

type TransportNode struct {
	node interfaces.NodeInterface // dependency injection

	tcp      *TCP
	registry *Registry

	sessionManager *session.SessionManager
}

func Init() (*TransportNode, error) {
	tn := TransportNode{
		tcp:      new(TCP),
		registry: &Registry{},

		sessionManager: session.CreateSessionManager(),
	}

	tn.registry.AddCallBack(0x01, tn.ExecAuth)
	tn.registry.AddCallBack(0x02, tn.ExecAuthAck)
	tn.registry.AddCallBack(0x03, tn.ExecFrame)

	return &tn, nil
}

func (tn *TransportNode) SetNode(n interfaces.NodeInterface) {
	tn.node = n
	if err := tn.tcp.Init(n.GetConfig().TcpPort, tn.registry, tn.sessionManager); err != nil {
		log.Err(err).Msg("")
	}
}

func (tn *TransportNode) GetSessionManager() *session.SessionManager {
	return tn.sessionManager
}

func (tn *TransportNode) SendTCP(session *session.Session, data []byte) {
	tn.tcp.Send(session, data)
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

func (tn *TransportNode) Cleanup() {
	// close all sessions
	sessions := tn.sessionManager.GetAllSessions()
	for _, session := range sessions {
		ip, _ := session.To()
		log.Info().Msgf("disconnecting from: %v", ip)
		tn.tcp.Close(session)
	}
}
