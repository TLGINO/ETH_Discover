package node

import (
	"fmt"
	"go_fun/messages"
)

func (n *Node) ExecPing(m messages.Packet) {
	ping := m.Data.(*messages.Ping)
	fmt.Printf("processing ping: %s\n", ping)
}

func (n *Node) ExecPong(m messages.Packet) {
	pong := m.Data.(*messages.Pong)
	fmt.Printf("processing pong: %s\n", pong)
	n.discoveryMessagesLock.Lock()
	defer n.discoveryMessagesLock.Unlock()

	ch, exists := n.discoveryMessages[pong.PingHash]
	if exists {
		ch <- m
	} else {
		fmt.Printf("unsolicited pong received")
	}
}
