// node/node.go
package node

import (
	"fmt"
	"go_fun/devp2p"
	"go_fun/network"
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
	toIP := net.ParseIP("157.90.35.166")
	toUDPPort := uint16(30303)
	toTCPPort := uint16(30303)

	ping := &devp2p.Ping{
		Version: 4,
		From: devp2p.Endpoint{
			IP:  myIP,
			UDP: myUDPPort,
			TCP: myTCPPort,
		},
		To: devp2p.Endpoint{
			IP:  toIP,
			UDP: toUDPPort,
			TCP: toTCPPort,
		},
		Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
	}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("error generating private key: " + err.Error())
	}

	packet, err := devp2p.EncodePacket(privateKey, ping.Type(), ping)
	if err != nil {
		return fmt.Errorf("error encoding packet: " + err.Error())
	}
	to := toIP.String() + ":" + strconv.Itoa(int(toUDPPort))
	err = udpConn.Send(to, packet)
	if err != nil {
		return fmt.Errorf("error sending: " + err.Error())
	}
	return nil
}
