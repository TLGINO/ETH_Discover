package transport

import (
	"eth_discover/interfaces"
	"eth_discover/session"
	"net"
	"strconv"
)

type TransportNode struct {
	node interfaces.NodeInterface // dependency injection

	tcp            *TCP
	sessionManager *session.SessionManager
}

func Init() (*TransportNode, error) {
	tn := TransportNode{
		tcp:            new(TCP),
		sessionManager: session.CreateSessionManager(),
	}
	if err := tn.tcp.Init(tn.sessionManager); err != nil {
		return nil, err
	}
	return &tn, nil
}

func (tn *TransportNode) SetNode(n interfaces.NodeInterface) {
	tn.node = n
}

func (tn *TransportNode) SendTCP(toIP net.IP, toPort uint16, data []byte) error {
	var toAddr string
	if toIP.To4() != nil {
		toAddr = toIP.String() + ":" + strconv.Itoa(int(toPort))
	} else {
		toAddr = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
	}
	return tn.tcp.Send(toAddr, data)
}
