// network/socket.go
package network

import (
	"fmt"
	"go_fun/serializer"
	"net"
)

// implements Connection
type UDP struct {
	conn *net.UDPConn
	port uint16
}

func (u *UDP) Init() error {
	u.port = 8000
	// addr := ":" + strconv.Itoa(int(u.port))
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

	go u.handleConnections()
	return nil
}

func (u *UDP) GetPort() uint16 {
	return u.port
}

func (u *UDP) handleConnections() {
	buf := make([]byte, 1024)
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

	fmt.Printf("Received from %s (UDP): %s", addr.String(), string(data))

	packet, err := serializer.DeserializePacket(data)

	if err == nil {
		if packet.Header.Type == 1 {
			ping := packet.Data.(*serializer.Ping)
			println("Ping: ", ping.String())
		} else if packet.Header.Type == 2 {
			pong := packet.Data.(*serializer.Pong)
			println("Pong: ", pong.String())
		}
	}
}

func (u *UDP) Send(to string, data []byte) error {
	// to := ip + ":" + port
	println("HERE TO: " + to)
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
