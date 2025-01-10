package node

import (
	"fmt"
	"go_fun/messages"
	"strconv"
)

func (n *Node) ExecPing(m messages.Packet) {
	ping := m.Data.(*messages.Ping)
	fmt.Printf("processing ping: %s\n", ping)

	pongPacket, err := messages.NewPongPacket(ping.From, m.Header.Hash, ping.Expiration)
	if err != nil {
		fmt.Printf("error creating pong: %s\n", err)
		return
	}

	pongData, err := pongPacket.Serialize()
	if err != nil {
		fmt.Printf("error serializing pong: %s\n", err)
	}

	toAddr := ping.From.IP.String() + ":" + strconv.Itoa(int(ping.From.UDP))

	err = n.SendUDP(toAddr, pongData)
	if err != nil {
		fmt.Printf("error sending: %s\n", err)
	}
	println("answered ping")
}

func (n *Node) ExecPong(m messages.Packet) {
	pong := m.Data.(*messages.Pong)
	fmt.Printf("processing pong: %s\n", pong)
	n.discoveryMessagesLock.Lock()
	defer n.discoveryMessagesLock.Unlock()

	ch, exists := n.discoveryMessages[pong.PingHash]
	if exists {
		ch <- m
	} else {
		fmt.Printf("unsolicited pong received")
	}
}
