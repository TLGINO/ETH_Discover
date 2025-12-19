package transport

import (
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/rs/zerolog/log"
)

type TCP struct {
	listener       net.Listener
	port           uint16
	sessionManager *session.SessionManager
	registry       *Registry      // <- dependency injection
	tn             *TransportNode // <- dependency injection
}

func (t *TCP) Init(port uint16, registry *Registry, sessionManager *session.SessionManager, tn *TransportNode) error {
	t.port = port
	addr := fmt.Sprintf(":%d", t.port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error creating TCP server: %v", err)
	}
	t.listener = listener
	t.sessionManager = sessionManager
	t.registry = registry
	t.tn = tn

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

		go t.handleIncomingConnection(conn)
	}
}

// handleIncomingConnection handles connections we accepted (incoming)
func (t *TCP) handleIncomingConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	ip, portStr, _ := net.SplitHostPort(remoteAddr)

	log.Debug().Msgf("Accepted incoming connection from %s", remoteAddr)

	// SIMPLE STRATEGY: Always create a new session for incoming connections
	// Don't try to match with outgoing sessions - keep them separate
	// Each connection gets its own session

	ephemeralSessionID := ip + ":" + portStr
	portInt, _ := strconv.Atoi(portStr)
	session := t.sessionManager.AddSession(ephemeralSessionID, net.ParseIP(ip), uint16(portInt))
	log.Debug().Msgf("Created new session for incoming: %s", ephemeralSessionID)

	// Add connection to session
	session.AddConn(conn)

	defer func() {
		log.Debug().Msgf("Closing incoming connection from %s", remoteAddr)
		t.sessionManager.RemoveSession(ephemeralSessionID)
		conn.Close()
	}()

	// Start read loop
	t.readLoop(conn, session, "incoming")
}

// handleOutgoingConnection handles connections we initiated (outgoing)
func (t *TCP) handleOutgoingConnection(conn net.Conn, session *session.Session) {
	remoteAddr := conn.RemoteAddr().String()
	log.Debug().Msgf("Started reader for outgoing connection to %s (session: %s)", remoteAddr, session.GetID())

	defer func() {
		log.Debug().Msgf("Closing outgoing connection to %s", remoteAddr)
		conn.Close()
	}()

	// Start read loop
	t.readLoop(conn, session, "outgoing")
}

// readLoop is the common read loop for both incoming and outgoing connections
func (t *TCP) readLoop(conn net.Conn, session *session.Session, connType string) {
	firstPacket := true
	for {
		// Use the session as-is - no lookups needed
		currentSession := session

		// Deserialize message
		packet, pType, err := rlpx.DeserializePacket(conn, currentSession, !firstPacket)
		if err != nil {
			if err == io.EOF {
				log.Warn().Msgf("[%s] Connection closed by remote: %v", connType, conn.RemoteAddr())
				return
			}

			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				log.Warn().Msgf("[%s] Connection closed: %v", connType, conn.RemoteAddr())
				return
			}

			log.Error().Err(err).Msgf("[%s] Error deserializing packet from %v", connType, conn.RemoteAddr())
			continue
		}

		// Execute callback
		log.Debug().Msgf("[%s] Received packet type %v on session %s", connType, pType, currentSession.GetID())
		t.registry.ExecCallBack(packet, pType, currentSession)
		firstPacket = false
	}
}

func (t *TCP) Send(session *session.Session, data []byte) {
	// Check if we already have a connection to this address
	conn, found := session.GetConn()

	if !found {
		toIP, toPort := session.To()
		log.Debug().Msgf("Opening new outgoing connection to %s:%d for session %s", toIP.String(), toPort, session.GetID())
		to := net.JoinHostPort(toIP.String(), strconv.Itoa(int(toPort)))

		// Open connection
		newConn, err := net.Dial("tcp", to)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to connect to %s", to)
			t.Close(session)
			return
		}

		// Add connection to session
		session.AddConn(newConn)
		log.Debug().Msgf("Connected to %s (local: %s)", newConn.RemoteAddr(), newConn.LocalAddr())

		// CRITICAL: Start reader for this outgoing connection
		go t.handleOutgoingConnection(newConn, session)

		conn = newConn
	} else {
		toIP, toPort := session.To()
		log.Debug().Msgf("Using existing connection for %s:%d", toIP.String(), toPort)
	}

	// Send data
	log.Debug().Msgf("Sending %d bytes to %s (session: %s)", len(data), conn.RemoteAddr(), session.GetID())
	_, err := conn.Write(data)
	if err != nil {
		log.Error().Err(err).Msgf("Error sending to %s", conn.RemoteAddr())
		t.Close(session)
		return
	}
}

// UpdateSessionPort - not used since ListenPort is always 0
func (t *TCP) UpdateSessionPort(oldSession *session.Session, newPort uint16) *session.Session {
	return oldSession
}

func (t *TCP) Close(session *session.Session) {
	conn, found := session.GetConn()

	if found {
		log.Debug().Msgf("Closing connection for session %s", session.GetID())
		conn.Close()
	}

	session_id := session.GetID()
	t.sessionManager.RemoveSession(session_id)
	log.Debug().Msgf("Removed session %s", session_id)

	// Find enode to reset
	_, nodeID := session.GetNodeID()
	allENodeTuples := t.tn.node.GetAllENodes()
	for _, enode := range allENodeTuples {
		if enode.Enode.ID == nodeID {
			t.tn.node.UpdateENode(&enode.Enode, interfaces.NotBondedENode)
			return
		}
	}
}
