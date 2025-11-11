package transport

import (
	_ "github.com/mattn/go-sqlite3"

	"eth_discover/interfaces"
	"eth_discover/session"

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
	if err := tn.tcp.Init(n.GetConfig().TcpPort, tn.registry, tn.sessionManager, tn); err != nil {
		log.Err(err).Msg("")
	}
}

func (tn *TransportNode) GetSessionManager() *session.SessionManager {
	return tn.sessionManager
}

func (tn *TransportNode) SendTCP(session *session.Session, data []byte) {
	tn.tcp.Send(session, data)
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
