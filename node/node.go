// node/node.go
package node

import (
	"encoding/json"
	"eth_discover/enr"
	G "eth_discover/global"
	"eth_discover/interfaces"
	"eth_discover/node/discovery"
	"eth_discover/node/transport"
	"fmt"
	"net"
	"net/http"

	"github.com/rs/zerolog/log"
)

type Node struct {
	interfaces.NodeInterface

	discoveryNode *discovery.DiscoveryNode
	transportNode *transport.TransportNode

	enr *enr.ENR

	config *interfaces.Config
}

// interface function
func Init(config *interfaces.Config, testEnode *interfaces.ENode) (*Node, error) {

	if true {
		// if config.Ip.String() == "" || config.Ip.String() == "auto" {
		config.Ip = getPublicIP()
	}
	// config := &interfaces.Config{
	// 	Ip:      getPublicIP(),
	// 	UdpPort: 30303,
	// 	TcpPort: 30303,
	// }

	log.Info().Msg("Config: " + config.String())

	discovery_node, err := discovery.Init(testEnode) // dependency injection
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
		enr:           &enr.ENR{},

		config: config,
	}
	discovery_node.SetNode(n)
	transport_node.SetNode(n)

	n.enr.Set("ip", config.Ip)
	n.enr.Set("secp256k1", G.COMPRESSED_PUBLIC_KEY)
	n.enr.Set("udp", config.UdpPort)
	n.enr.Set("tcp", config.TcpPort)

	n.enr.Set("ip", config.Ip)
	n.enr.Set("secp256k1", G.COMPRESSED_PUBLIC_KEY)
	n.enr.Set("udp", config.UdpPort)
	n.enr.Set("tcp", config.TcpPort)

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

func (n *Node) GetDiscoveryNode() *discovery.DiscoveryNode {
	return n.discoveryNode
}

func (n *Node) GetTransportNode() *transport.TransportNode {
	return n.transportNode
}

func getPublicIP() net.IP {
	var ip struct {
		Query string `json:"query"`
	}
	resp, _ := http.Get("http://ip-api.com/json/")
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&ip)
	return net.ParseIP(ip.Query)
}
