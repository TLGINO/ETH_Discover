package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// Peer represents a node in the P2P network
type Peer struct {
	port        string
	listener    net.Listener
	connections map[string]net.Conn
	mu          sync.Mutex
}

func NewPeer(port string) *Peer {
	return &Peer{
		port:        port,
		connections: make(map[string]net.Conn),
	}
}

// StartListening begins accepting incoming connections
func (p *Peer) StartListening() error {
	listener, err := net.Listen("tcp", ":"+p.port)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	p.listener = listener

	fmt.Printf("[%s] Listening on :%s\n", p.port, p.port)

	go p.acceptLoop()
	return nil
}

func (p *Peer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			log.Printf("[%s] Accept error: %v\n", p.port, err)
			return
		}

		remoteAddr := conn.RemoteAddr().String()
		fmt.Printf("[%s] Incoming connection from %s\n", p.port, remoteAddr)

		p.mu.Lock()
		p.connections[remoteAddr] = conn
		p.mu.Unlock()

		// Start reading from this connection
		go p.readLoop(conn, remoteAddr)
	}
}

// ConnectTo initiates a connection to another peer
func (p *Peer) ConnectTo(targetPort string) error {
	addr := "127.0.0.1:" + targetPort

	fmt.Printf("[%s] Connecting to %s...\n", p.port, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}

	fmt.Printf("[%s] Connected to %s\n", p.port, conn.RemoteAddr())

	p.mu.Lock()
	p.connections[addr] = conn
	p.mu.Unlock()

	// Start reading from this connection
	go p.readLoop(conn, addr)

	return nil
}

func (p *Peer) readLoop(conn net.Conn, id string) {
	defer func() {
		conn.Close()
		p.mu.Lock()
		delete(p.connections, id)
		p.mu.Unlock()
		fmt.Printf("[%s] Connection closed: %s\n", p.port, id)
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		msg := scanner.Text()
		fmt.Printf("[%s] <- Received: %s (from %s)\n", p.port, msg, id)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[%s] Read error from %s: %v\n", p.port, id, err)
	}
}

// Broadcast sends a message to all connected peers
func (p *Peer) Broadcast(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conn := range p.connections {
		_, err := fmt.Fprintf(conn, "%s\n", msg)
		if err != nil {
			log.Printf("[%s] Failed to send to %s: %v\n", p.port, addr, err)
			continue
		}
		fmt.Printf("[%s] -> Sent: %s (to %s)\n", p.port, msg, addr)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run bidirectional.go <port> [connect_to_port]")
		fmt.Println("\nExamples:")
		fmt.Println("  Terminal 1: go run bidirectional.go 4000")
		fmt.Println("  Terminal 2: go run bidirectional.go 4001 4000")
		os.Exit(1)
	}

	myPort := os.Args[1]
	peer := NewPeer(myPort)

	// Start listening for incoming connections
	if err := peer.StartListening(); err != nil {
		log.Fatal(err)
	}

	// If a target port was provided, connect to it
	if len(os.Args) >= 3 {
		targetPort := os.Args[2]
		time.Sleep(500 * time.Millisecond) // Give other peer time to start

		if err := peer.ConnectTo(targetPort); err != nil {
			log.Printf("Warning: %v\n", err)
		}
	}

	// Send periodic messages
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		counter := 1
		for range ticker.C {
			msg := fmt.Sprintf("Message #%d from port %s at %s",
				counter, myPort, time.Now().Format("15:04:05"))
			peer.Broadcast(msg)
			counter++
		}
	}()

	// Keep running
	fmt.Printf("[%s] Running... Press Ctrl+C to exit\n", myPort)
	select {}
}
