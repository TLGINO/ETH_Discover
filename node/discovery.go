package node

import (
	"fmt"
	"go_fun/messages"
	"net"
	"strconv"
	"time"
)

var bootNode = []string{
	"18.138.108.67",
	"3.209.45.79",
	"65.108.70.101",
	"157.90.35.166",
}

// Bind binds a node
// Sends a Ping, awaits a corresponding Pong, returns the address of the binded bootnode
func (n *Node) Bind() (string, error) {
	server := n.GetServer()
	tcpConn := server.GetTCP()
	udpConn := server.GetUDP()

	myIP := server.GetPublicIP()
	myUDPPort := udpConn.GetPort()
	myTCPPort := tcpConn.GetPort()

	for _, bootNodeAddr := range bootNode {
		println(bootNodeAddr)
		toIP := net.ParseIP(bootNodeAddr)
		toUDPPort := uint16(30303)
		// toIP := net.ParseIP("127.0.0.1")
		// toUDPPort := myUDPPort

		from := messages.Endpoint{
			IP:  myIP,
			UDP: myUDPPort,
			TCP: myTCPPort,
		}
		to := messages.Endpoint{
			IP:  toIP,
			UDP: toUDPPort,
			TCP: 0,
		}

		expiration := uint64(time.Now().Add(50 * time.Second).Unix())

		pingPacket, err := messages.NewPingPacket(4, from, to, expiration)
		if err != nil {
			return "", fmt.Errorf("error creating ping: " + err.Error())
		}

		pingData, err := pingPacket.Serialize()
		if err != nil {
			return "", fmt.Errorf("error serializing ping: " + err.Error())
		}

		toAddr := toIP.String() + ":" + strconv.Itoa(int(toUDPPort))

		err = n.SendUDP(toAddr, pingData)
		if err != nil {
			return "", fmt.Errorf("error sending: " + err.Error())
		}

		ch := make(chan messages.Packet)
		n.discoveryMessagesLock.Lock()
		n.discoveryMessages[pingPacket.Header.Hash] = ch
		n.discoveryMessagesLock.Unlock()

		defer func() {
			n.discoveryMessagesLock.Lock()
			delete(n.discoveryMessages, pingPacket.Header.Hash)
			n.discoveryMessagesLock.Unlock()

		}()

		select {
		case <-ch:
			fmt.Println("Received pong response!")
			return bootNodeAddr, nil
		case <-time.After(5 * time.Second):
			fmt.Println("Timeout waiting for pong response, trying with new node")
		}

	}
	return "", fmt.Errorf("error performing bind, no one responded")
}
