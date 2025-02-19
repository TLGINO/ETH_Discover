package transport

import (
	"eth_discover/interfaces"
	"eth_discover/session"
	"net"
	"strconv"

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

func (tn *TransportNode) SendTCP(toIP net.IP, toPort uint16, data []byte) {
	var toAddr string
	if toIP.To4() != nil {
		toAddr = toIP.String() + ":" + strconv.Itoa(int(toPort))
	} else {
		toAddr = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
	}
	tn.tcp.Send(toAddr, data)
}
