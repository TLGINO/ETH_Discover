package discovery

import (
	"eth_discover/discv4"
	"fmt"
	"time"
)

func (dn *DiscoveryNode) ExecPing(m discv4.Packet, from string) {
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

	err = dn.SendUDP(ping.From.IP, ping.From.UDP, pongData)
	if err != nil {
		fmt.Printf("error sending: %s\n", err)
	}
}

func (dn *DiscoveryNode) ExecPong(m discv4.Packet, from string) {
	pong := m.Data.(*discv4.Pong)
	fmt.Printf("received pong\n")

	ch := dn.GetAwaitPong(pong.PingHash)
	if ch != nil {
		ch <- struct{}{}
	} else {
		fmt.Printf("unsolicited or delayed pong message received")
	}
}
func (dn *DiscoveryNode) ExecFindNode(m discv4.Packet, from string) {
	findNode := m.Data.(*discv4.FindNode)
	fmt.Printf("received findNode: %s\n", findNode)
	// [TODO] respond
}
func (dn *DiscoveryNode) ExecNeighbors(m discv4.Packet, from string) {
	neighbors := m.Data.(*discv4.Neighbors)
	fmt.Printf("received neighbors: %d\n", len(neighbors.Nodes))

	for _, enode := range neighbors.Nodes {
		dn.AddENode(&enode)
	}

	ch := dn.GetAwaitNeighbours(from)
	if ch != nil {
		select {
		case ch <- struct{}{}:
			// Successfully sent
		default:
			fmt.Printf("channel full or closed for neighbour response from %s\n", from)
		}
	} else {
		fmt.Printf("unsolicited or delayed neighbour message received from %s\n", from)
	}
}
func (dn *DiscoveryNode) ExecENRRequest(m discv4.Packet, from string) {
	enrRequest := m.Data.(*discv4.ENRRequest)
	fmt.Printf("received enrRequest: %s\n", enrRequest)
	// [TODO] respond
}
func (dn *DiscoveryNode) ExecENRResponse(m discv4.Packet, from string) {
	enrResponse := m.Data.(*discv4.ENRResponse)
	fmt.Printf("received enrResponse: %s\n", enrResponse)
}
