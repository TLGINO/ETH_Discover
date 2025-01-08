// node/node.go
package node

import (
	"fmt"
	"go_fun/network"
	"go_fun/serializer"
	"net"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type Node struct {
	server *network.Server
}

func Init() (*Node, error) {
	n := &Node{
		server: &network.Server{},
	}

	// Start server in goroutine
	go func() {
		if err := n.server.InitServer(); err != nil {
			println("Server error:", err.Error())
		}
	}()

	return n, nil
}

func (n *Node) GetServer() *network.Server {
	return n.server
}

func (n *Node) SendPing() error {
	server := n.GetServer()
	tcpConn := server.GetTCP()
	udpConn := server.GetUDP()

	myIP := server.GetPublicIP()
	myUDPPort := udpConn.GetPort()
	myTCPPort := tcpConn.GetPort()
	// toIP := net.ParseIP("157.90.35.166")
	// toIP := net.ParseIP("65.108.70.101")
	// toUDPPort := uint16(30303)
	// toTCPPort := uint16(30303)

	toIP := net.ParseIP("127.0.0.1")
	toUDPPort := myUDPPort
	toTCPPort := myTCPPort

	from := serializer.Endpoint{
		IP:  myIP,
		UDP: myUDPPort,
		TCP: myTCPPort,
	}
	to := serializer.Endpoint{
		IP:  toIP,
		UDP: toUDPPort,
		TCP: toTCPPort,
	}

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("error generating private key: " + err.Error())
	}
	pingMsg, err := serializer.NewPing(uint64(4), from, to, expiration, privateKey)
	if err != nil {
		return fmt.Errorf("error creating ping: " + err.Error())
	}

	toAddr := toIP.String() + ":" + strconv.Itoa(int(toUDPPort))

	err = udpConn.Send(toAddr, pingMsg)
	if err != nil {
		return fmt.Errorf("error sending: " + err.Error())
	}
	return nil
}
