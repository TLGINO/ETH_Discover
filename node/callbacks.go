package node

import (
	"fmt"
	"go_fun/discv4"
	"strconv"
	"time"
)

func (n *Node) ExecPing(m discv4.Packet) {
	ping := m.Data.(*discv4.Ping)
	fmt.Printf("received ping\n")

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())
	pongPacket, err := discv4.NewPongPacket(ping.From, m.Header.Hash, expiration)
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

func (n *Node) ExecPong(m discv4.Packet) {
	pong := m.Data.(*discv4.Pong)
	fmt.Printf("received pong\n")

	ch := n.GetAwaitPong(pong.PingHash)
	if ch != nil {
		ch <- m
	} else {
		fmt.Printf("unsolicited pong received")
	}
}
func (n *Node) ExecFindNode(m discv4.Packet) {
	findNode := m.Data.(*discv4.FindNode)
	fmt.Printf("received findNode: %s\n", findNode)
}
func (n *Node) ExecNeighbors(m discv4.Packet) {
	neighbors := m.Data.(*discv4.Neighbors)
	fmt.Printf("received neighbors: %d\n", len(neighbors.Nodes))
	for _, enode := range neighbors.Nodes {
		n.AddENode(&enode)
	}
	fmt.Println("Total found nodes: ", len(n.GetAllENodes()))
}
func (n *Node) ExecENRRequest(m discv4.Packet) {
	enrRequest := m.Data.(*discv4.ENRRequest)
	fmt.Printf("received enrRequest: %s\n", enrRequest)
	// [TODO] respond
}
func (n *Node) ExecENRResponse(m discv4.Packet) {
	enrResponse := m.Data.(*discv4.ENRResponse)
	fmt.Printf("received enrResponse: %s\n", enrResponse)
}
