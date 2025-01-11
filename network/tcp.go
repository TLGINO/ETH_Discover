// network/socket.go
package network

import (
	"fmt"
	"go_fun/messages"
	"net"
)

// implements Connection
type TCP struct {
	listener    net.Listener
	connections map[string]*net.Conn
	port        uint16
	registry    *messages.Registry // <- dependency injection

}

func (t *TCP) Init(registry *messages.Registry) error {
	t.port = 30303
	addr := fmt.Sprintf(":%d", t.port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error creating TCP server: %v", err)
	}
	t.listener = listener
	t.registry = registry

	go t.handleConnections()
	return nil
}

func (t *TCP) GetPort() uint16 {
	return t.port
}

func (t *TCP) handleConnections() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			fmt.Println("TCP accept error:", err)
			continue
		}
		t.connections[conn.LocalAddr().Network()] = &conn
		go t.handleConnection(conn)
	}
}

func (t *TCP) handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("TCP read error:", err)
			return
		}
		fmt.Printf("Received from %s (TCP): %s", conn.RemoteAddr().String(), string(buf[:n]))
	}
}

func (t *TCP) Send(to string, data []byte) error {
	// to := ip + port
	conn, err := net.Dial("tcp", to)
	if err != nil {
		return fmt.Errorf("TCP dial error: %v", err)
	}

	defer conn.Close() // [TODO] check if this is good...

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("error sending via tcp:", err.Error())
	}

	return nil
}
