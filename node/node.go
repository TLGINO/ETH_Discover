// node/node.go
package node

import (
	"eth_discover/interfaces"
	"eth_discover/node/discovery"
	"eth_discover/node/transport"
	"fmt"

	"github.com/rs/zerolog/log"
)

type Node struct {
	interfaces.NodeInterface

	discoveryNode *discovery.DiscoveryNode
	transportNode *transport.TransportNode

	config *interfaces.Config

	tracker interfaces.TrackerInterface
}

// interface function
func Init(config *interfaces.Config) (*Node, error) {
	log.Info().Msg("Config: " + config.String())

	discovery_node, err := discovery.Init()
	if err != nil {
		return nil, fmt.Errorf("error creating discovery node: %v", err)
	}

	transport_node, err := transport.Init() // dependency injection
	if err != nil {
		return nil, fmt.Errorf("error creating transport node: %v", err)
	}

	n := &Node{
		discoveryNode: discovery_node,
		transportNode: transport_node,

		config:  config,
		tracker: &Tracker{},
	}
	discovery_node.SetNode(n)
	transport_node.SetNode(n)

	// n.enr.Set("ip", config.Ip)
	// n.enr.Set("secp256k1", G.COMPRESSED_PUBLIC_KEY)
	// n.enr.Set("udp", config.UdpPort)
	// n.enr.Set("tcp", config.TcpPort)

	return n, nil
}

// interface function
func (n *Node) GetConfig() *interfaces.Config {
	return n.config
}

// interface function
func (n *Node) GetAllENodes() []interfaces.EnodeTuple {
	return n.discoveryNode.GetAllENodes()
}

// interface function
func (n *Node) TestAndSetEnode(e *interfaces.ENode, oldState, newState interfaces.ENodeState) bool {
	return n.discoveryNode.TestAndSetEnode(e, oldState, newState)
}

// interface function
func (n *Node) UpdateENode(e *interfaces.ENode, state interfaces.ENodeState) {
	n.discoveryNode.UpdateENode(e, state)
}

func (n *Node) GetDiscoveryNode() *discovery.DiscoveryNode {
	return n.discoveryNode
}

func (n *Node) GetTransportNode() *transport.TransportNode {
	return n.transportNode
}

func (n *Node) GetTracker() interfaces.TrackerInterface {
	return n.tracker
}
