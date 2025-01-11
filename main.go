// main.go
package main

import (
	"fmt"
	"go_fun/node"
	"time"
)

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
	}

	select {}
}
