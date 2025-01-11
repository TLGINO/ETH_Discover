package node

import (
	"fmt"
	"go_fun/messages"
	"strconv"
	"time"
)

// Bind binds a node
// Sends a Ping, awaits a corresponding Pong, returns the address of the binded bootnode
func (n *Node) Bind() {
	server := n.GetServer()
	tcpConn := server.GetTCP()
	udpConn := server.GetUDP()

	myIP := server.GetPublicIP()
	myUDPPort := udpConn.GetPort()
	myTCPPort := tcpConn.GetPort()

	allENodes := n.GetAllENodes()
	var filteredENodes []*messages.ENode
	for eNode, state := range allENodes {
		if state == NotBondedENode {
			filteredENodes = append(filteredENodes, eNode)
		}
	}

	for _, eNode := range filteredENodes {

		from := messages.Endpoint{
			IP:  myIP,
			UDP: myUDPPort,
			TCP: myTCPPort,
		}
		to := messages.Endpoint{
			IP:  eNode.IP,
			UDP: eNode.UDP,
			TCP: 0,
		}

		expiration := uint64(time.Now().Add(50 * time.Second).Unix())

		pingPacket, err := messages.NewPingPacket(4, from, to, expiration)
		if err != nil {
			fmt.Print("error creating ping: " + err.Error())
			continue
		}

		pingData, err := pingPacket.Serialize()
		if err != nil {
			fmt.Print("error serializing ping: " + err.Error())
			continue
		}

		toAddr := eNode.IP.String() + ":" + strconv.Itoa(int(eNode.UDP))
		err = n.SendUDP(toAddr, pingData)
		if err != nil {
			fmt.Print("error sending: " + err.Error())
			continue
		}

		ch := make(chan messages.Packet)
		n.AddAwaitPong(pingPacket.Header.Hash, ch)

		defer func() {
			n.RemoveAwaitPong(pingPacket.Header.Hash)
		}()

		select {
		case <-ch:
			fmt.Printf("Bonded with node: %x\n", eNode.ID)
			n.UpdateENode(eNode, BondedENode)
		case <-time.After(1 * time.Second):
			fmt.Println("Timeout waiting for pong response, trying with new node")
		}

	}
}

func (n *Node) Find() {

	allENodes := n.GetAllENodes()
	var filteredENodes []*messages.ENode
	for eNode, state := range allENodes {
		if state == BondedENode {
			filteredENodes = append(filteredENodes, eNode)
		}
	}

	for _, eNode := range filteredENodes {
		expiration := uint64(time.Now().Add(50 * time.Second).Unix())

		findNodePacket, err := messages.NewFindNodePacket(expiration)
		if err != nil {
			fmt.Print("error creating findNode: " + err.Error())
			continue
		}

		findNodeData, err := findNodePacket.Serialize()
		if err != nil {
			fmt.Print("error serializing findNode: " + err.Error())
			continue
		}

		toAddr := eNode.IP.String() + ":" + strconv.Itoa(int(eNode.UDP))
		err = n.SendUDP(toAddr, findNodeData)
		if err != nil {
			fmt.Print("error sending: " + err.Error())
			continue
		}
		// for now simply consider that after waiting 1s, we have received a neighbour from this node

		time.Sleep(1 * time.Second)
		n.UpdateENode(eNode, AnsweredFindNode)
	}
}
