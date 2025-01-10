// node/node.go
package node

import (
	"go_fun/messages"
	"go_fun/network"
	"sync"
)

type Node struct {
	server   *network.Server
	registry *messages.Registry

	discoveryMessages     map[[32]byte]chan (messages.Packet) // discovery hash -> pong
	discoveryMessagesLock sync.Mutex
}

func Init() (*Node, error) {
	n := &Node{
		server:            &network.Server{},
		registry:          &messages.Registry{},
		discoveryMessages: make(map[[32]byte]chan messages.Packet),
	}

	messages.CreatePK() // create this node's private key

	n.registry.AddCallBack(0x01, n.ExecPing)
	n.registry.AddCallBack(0x02, n.ExecPong)

	go func() {
		if err := n.server.InitServer(n.registry); err != nil {
			println("Server error:", err.Error())
		}
	}()

	return n, nil
}

func (n *Node) GetServer() *network.Server {
	return n.server
}

func (n *Node) SendUDP(to string, data []byte) error {
	s := n.GetServer()
	con := s.GetUDP()
	return con.Send(to, data)
}
