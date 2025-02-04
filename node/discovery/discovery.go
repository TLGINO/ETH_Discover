package discovery

import (
	"eth_discover/discv4"
	"eth_discover/interfaces"
	"fmt"
	"time"
)

// Bind binds a node
// Sends a Ping, awaits a corresponding Pong, returns the address of the binded bootnode
func (dn *DiscoveryNode) Bind() {
	allENodeTuples := dn.GetAllENodes()
	var filteredENodes []*interfaces.ENode
	for _, enodeTuple := range allENodeTuples {
		if enodeTuple.State == interfaces.NotBondedENode {
			filteredENodes = append(filteredENodes, &enodeTuple.Enode)
		}
	}

	config := dn.node.GetConfig()
	from := discv4.Endpoint{
		IP:  config.Ip,
		UDP: config.UdpPort,
		TCP: config.TcpPort,
	}

	type nodeResponse struct {
		enode *interfaces.ENode
		hash  [32]byte
		ch    chan struct{}
	}

	responses := make([]nodeResponse, 0, len(filteredENodes))

	for _, eNode := range filteredENodes {

		to := discv4.Endpoint{
			IP:  eNode.IP,
			UDP: eNode.UDP,
			TCP: 0,
		}

		expiration := uint64(time.Now().Add(50 * time.Second).Unix())

		pingPacket, err := discv4.NewPingPacket(4, from, to, expiration)
		if err != nil {
			fmt.Print("error creating ping: " + err.Error())
			continue
		}

		pingData, err := pingPacket.Serialize()
		if err != nil {
			fmt.Print("error serializing ping: " + err.Error())
			continue
		}

		ch := make(chan struct{})
		responses = append(responses, nodeResponse{enode: eNode, hash: pingPacket.Header.Hash, ch: ch})
		dn.AddAwaitPong(pingPacket.Header.Hash, ch)

		err = dn.SendUDP(eNode.IP, eNode.UDP, pingData)
		if err != nil {
			fmt.Print("error sending: " + err.Error())
			continue
		}

	}

	responseTimeout := 500 * time.Millisecond
	for _, resp := range responses {
		select {
		case <-resp.ch:
			fmt.Printf("Bonded with node: %x\n", resp.enode.ID)
			dn.UpdateENode(resp.enode, interfaces.BondedENode)
		case <-time.After(responseTimeout):
			fmt.Println("Timeout waiting for pong response, trying with new node")
		}
		// Clean up
		dn.RemoveAwaitPong(resp.hash)
	}
}

func (dn *DiscoveryNode) Find() {

	allENodeTuples := dn.GetAllENodes()
	var filteredENodes []*interfaces.ENode
	for _, enodeTuple := range allENodeTuples {
		if enodeTuple.State == interfaces.BondedENode {
			filteredENodes = append(filteredENodes, &enodeTuple.Enode)
		}
	}

	type nodeResponse struct {
		enode *interfaces.ENode
		ch    chan struct{}
	}

	responses := make([]nodeResponse, 0, len(filteredENodes))

	for _, eNode := range filteredENodes {
		expiration := uint64(time.Now().Add(50 * time.Second).Unix())

		findNodePacket, err := discv4.NewFindNodePacket(expiration)
		if err != nil {
			fmt.Print("error creating findNode: " + err.Error())
			continue
		}

		findNodeData, err := findNodePacket.Serialize()
		if err != nil {
			fmt.Print("error serializing findNode: " + err.Error())
			continue
		}

		ch := make(chan struct{})
		responses = append(responses, nodeResponse{enode: eNode, ch: ch})
		dn.AddAwaitNeighbours(eNode.IP.String(), ch)

		err = dn.SendUDP(eNode.IP, eNode.UDP, findNodeData)
		if err != nil {
			fmt.Print("error sending: " + err.Error())
			dn.RemoveAwaitNeighbours(eNode.IP.String())
			continue
		}

	}

	responseTimeout := 500 * time.Millisecond
	for _, resp := range responses {
		select {
		case <-resp.ch:
			fmt.Printf("Received Neighbours from node %s\n", resp.enode.IP.String())
			dn.UpdateENode(resp.enode, interfaces.AnsweredFindNode)
		case <-time.After(responseTimeout):
			fmt.Printf("Timeout waiting for neighbours from %s\n", resp.enode.IP.String())
		}
		// Clean up
		dn.RemoveAwaitNeighbours(resp.enode.IP.String())
	}
}
