// main.go
package main

import (
	"fmt"
	G "go_fun/global"
	"go_fun/node"
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

	for {
		// Bind to new nodes
		n.Bind()
		// Find new nodes
		n.Find()
		// can probably stop discovery once 10 nodes reached for now
		numNeigbors := len(n.GetAllENodes())
		if numNeigbors >= 10 {
			fmt.Printf("Stopping discovery process, connected to %d nodes\n", numNeigbors)
			break
		}
	}

	select {}
}
