package node

import (
	"fmt"
	"go_fun/messages"
	"strconv"
	"time"
)

func (n *Node) ExecPing(m messages.Packet) {
	ping := m.Data.(*messages.Ping)
	fmt.Printf("received ping\n")

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())
	pongPacket, err := messages.NewPongPacket(ping.From, m.Header.Hash, expiration)
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
}

func (n *Node) ExecPong(m messages.Packet) {
	pong := m.Data.(*messages.Pong)
	fmt.Printf("received pong\n")

	ch := n.GetAwaitPong(pong.PingHash)
	if ch != nil {
		ch <- m
	} else {
		fmt.Printf("unsolicited pong received")
	}
}
func (n *Node) ExecNeighbors(m messages.Packet) {
	neighbors := m.Data.(*messages.Neighbors)
	fmt.Printf("received neighbors: %s\n", neighbors)
}
