// network/socket.go
package network

import (
	"fmt"
	"go_fun/messages"
	"net"
	"sync"
)

// implements Connection
type UDP struct {
	conn     *net.UDPConn
	port     uint16
	registry *messages.Registry // <- dependency injection

	messageLock sync.Mutex
}

func (u *UDP) Init(registry *messages.Registry) error {
	u.port = 30303
	addr := fmt.Sprintf(":%d", u.port)

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("error resolving UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("error creating UDP server: %v", err)
	}
	u.conn = conn
	u.registry = registry

	go u.handleConnections()
	return nil
}

func (u *UDP) GetPort() uint16 {
	return u.port
}

func (u *UDP) handleConnections() {
	buf := make([]byte, 1280) // Max packet size
	for {
		n, addr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("UDP read error:", err)
			continue
		}
		go u.handleConnection(buf[:n], addr)
	}
}

func (u *UDP) handleConnection(data []byte, addr *net.UDPAddr) {
	u.messageLock.Lock()
	defer u.messageLock.Unlock()
	fmt.Printf("Received data (UDP) from: %s size %d\n", addr.String(), len(data))

	packet, err := messages.DeserializePacket(data)
	if err != nil {
		println("error in received udp data: " + err.Error())
		return
	}

	u.registry.ExecCallBack(packet)

}

func (u *UDP) Send(to string, data []byte) error {
	addr, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		return fmt.Errorf("error resolving UDP address: %v", err)
	}

	_, err = u.conn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("error sending via udp:", err.Error())
	}
	return nil
}
