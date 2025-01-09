// node/node.go
package node

import (
	"fmt"
	"go_fun/messages"
	"go_fun/network"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
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

func (n *Node) SendPing() error {
	server := n.GetServer()
	tcpConn := server.GetTCP()
	udpConn := server.GetUDP()

	myIP := server.GetPublicIP()
	myUDPPort := udpConn.GetPort()
	myTCPPort := tcpConn.GetPort()
	toIP := net.ParseIP("157.90.35.166")
	// toIP := net.ParseIP("65.108.70.101")
	toUDPPort := uint16(30303)
	toTCPPort := uint16(30303)

	// toIP := net.ParseIP("127.0.0.1")
	// toUDPPort := myUDPPort
	// toTCPPort := myTCPPort

	from := messages.Endpoint{
		IP:  myIP,
		UDP: myUDPPort,
		TCP: myTCPPort,
	}
	to := messages.Endpoint{
		IP:  toIP,
		UDP: toUDPPort,
		TCP: toTCPPort,
	}

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("error generating private key: " + err.Error())
	}

	pingPacket, err := messages.NewPingPacket(4, from, to, expiration, privateKey)
	if err != nil {
		return fmt.Errorf("error creating ping: " + err.Error())
	}

	pingData, err := pingPacket.Serialize()
	if err != nil {
		return fmt.Errorf("error serializing ping: " + err.Error())
	}

	toAddr := toIP.String() + ":" + strconv.Itoa(int(toUDPPort))

	err = udpConn.Send(toAddr, pingData)
	if err != nil {
		return fmt.Errorf("error sending: " + err.Error())
	}

	ch := make(chan messages.Packet)
	n.discoveryMessagesLock.Lock()
	n.discoveryMessages[pingPacket.Header.Hash] = ch
	n.discoveryMessagesLock.Unlock()

	select {
	case <-ch:
		fmt.Println("Received pong response!")
	case <-time.After(time.Duration(expiration) * time.Second):
		fmt.Println("Timeout waiting for pong response")
	}

	n.discoveryMessagesLock.Lock()
	delete(n.discoveryMessages, pingPacket.Header.Hash)
	n.discoveryMessagesLock.Unlock()
	return nil
}

var MainnetBootnodes = []string{
	"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
	"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
	"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
}
