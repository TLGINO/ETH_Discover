// main.go
package main

import (
	G "eth_discover/global"
	"eth_discover/node"
	"fmt"
	"time"
)

func init() {
	G.CreatePK()
}

func main() {
	n, err := node.Init()
	if err != nil {
		fmt.Println("Init error:", err.Error())
		return
	}

	// Give the server time to start
	time.Sleep(time.Second)

	discovery_node := n.GetDiscoveryNode()
	transport_node := n.GetTransportNode()
	for {

		// Bind to new nodes
		discovery_node.Bind()
		// Find new nodes
		discovery_node.Find()

		// can probably stop discovery once 10 nodes reached for now
		numNeigbors := len(n.GetAllENodes())

		println("\n\n\n NUM:", numNeigbors, "\n\n\n")

		if numNeigbors >= 10 {
			fmt.Printf("Stopping discovery process, connected to %d nodes\n", numNeigbors)
			break
		}
	}

	transport_node.StartHandShake()

	select {}
}
