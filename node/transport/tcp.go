package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type TCP struct {
	listener       net.Listener
	connections    map[string]net.Conn // Changed from *net.Conn to net.Conn
	port           uint16
	sessionManager *session.SessionManager
	registry       *Registry // <- dependency injection

	mutex sync.RWMutex // Added mutex for thread safety
}

func (t *TCP) Init(port uint16, registry *Registry, sessionManager *session.SessionManager) error {
	t.port = port
	addr := fmt.Sprintf(":%d", t.port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error creating TCP server: %v", err)
	}
	t.connections = make(map[string]net.Conn)
	t.listener = listener
	t.sessionManager = sessionManager
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
			log.Err(err).Msg("TCP accept error")
			continue
		}

		// Store connection using remote address as key
		remoteAddr := conn.RemoteAddr().String()
		t.mutex.Lock()
		t.connections[remoteAddr] = conn
		t.mutex.Unlock()

		go t.handleConnection(conn)
	}
}

func (t *TCP) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr) // Extract IP address
	defer func() {
		conn.Close()
		t.mutex.Lock()
		delete(t.connections, remoteAddr)
		t.mutex.Unlock()
	}()

	buf := make([]byte, 2<<24) // Max 16MiB
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Err(err).Msg("TCP read error")
			return
		}

		var session *session.Session
		found := true
		session = t.sessionManager.GetSession(ip)
		if session == nil {
			found = false
			session = t.sessionManager.AddSession(net.ParseIP(ip), uint16(conn.RemoteAddr().(*net.TCPAddr).Port))
		}

		packet, pType, err := rlpx.DeserializePacket(buf[:n], session, found)
		if err != nil {
			log.Error().Err(err).Msg("error received tcp data")
			return
		}
		t.registry.ExecCallBack(packet, pType, session)
	}
}

func (t *TCP) Send(to string, data []byte) {
	// Check if we already have a connection to this address
	var conn net.Conn
	var err error

	t.mutex.RLock()
	conn, exists := t.connections[to]
	t.mutex.RUnlock()

	if !exists {
		// Create new connection if none exists
		conn, err = net.DialTimeout("tcp", to, 1*time.Second)
		if err != nil {
			log.Error().Err(err).Msgf("failed to connect to server")
			return
		}

		// Store the new connection
		t.mutex.Lock()
		t.connections[to] = conn
		t.mutex.Unlock()

		// Handle the connection in a separate goroutine
		go t.handleConnection(conn)
	}

	// Send data using the connection
	_, err = conn.Write(data)
	if err != nil {
		// Remove failed connection
		t.mutex.Lock()
		delete(t.connections, to)
		t.mutex.Unlock()
		log.Error().Err(err).Msg("error sending via tcp:")
		return
	}
}
