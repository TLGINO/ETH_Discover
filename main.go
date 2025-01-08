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

	err = n.SendPing()
	if err != nil {
		fmt.Println("error sending ping:", err.Error())
		return
	}

	select {}
}
