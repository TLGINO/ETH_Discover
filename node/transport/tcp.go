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

	// Try to find existing session by IP (in case we also connected to them)
	var session *session.Session
	var session_id string
	found := false

	for _, s := range t.sessionManager.GetAllSessions() {
		toIP, _ := s.To()
		if toIP.String() == ip {
			session = s
			session_id = s.GetID()
			found = true
			log.Debug().Msgf("Found existing session for IP %s: %s", ip, session_id)
			break
		}
	}

	// If not found, create new session with ephemeral port
	if !found {
		session_id = ip + ":" + portStr
		portInt, _ := strconv.Atoi(portStr)
		session = t.sessionManager.AddSession(session_id, net.ParseIP(ip), uint16(portInt))
		log.Debug().Msgf("Created new session for incoming: %s (ephemeral port)", session_id)
	}

	// Add connection to session
	session.AddConn(conn)

	defer func() {
		log.Debug().Msgf("Closing incoming connection from %s", remoteAddr)
		conn.Close()
	}()

	// Start read loop
	t.readLoop(conn, session, "incoming")
}

// handleOutgoingConnection handles connections we initiated (outgoing)
func (t *TCP) handleOutgoingConnection(conn net.Conn, session *session.Session) {
	remoteAddr := conn.RemoteAddr().String()
	log.Debug().Msgf("Started reader for outgoing connection to %s (session %s)", remoteAddr, session.GetID())

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
		// Get current session (might have been updated)
		currentSession := session
		ip, _ := session.To()

		// Try to get updated session from manager
		for _, s := range t.sessionManager.GetAllSessions() {
			toIP, _ := s.To()
			if toIP.String() == ip.String() {
				currentSession = s
				break
			}
		}

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
		// This allows us to receive responses (AuthAck, Hello, Status, etc.)
		go t.handleOutgoingConnection(newConn, session)

		// Get the connection from session
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

// UpdateSessionPort updates the session's target port after learning it from the Hello frame
func (t *TCP) UpdateSessionPort(oldSession *session.Session, newPort uint16) *session.Session {
	if newPort == 0 {
		log.Debug().Msgf("No listen port in Hello, keeping session %s", oldSession.GetID())
		return oldSession
	}

	oldID := oldSession.GetID()
	ip, _ := oldSession.To()
	newID := fmt.Sprintf("%s:%d", ip.String(), newPort)

	if oldID == newID {
		log.Debug().Msgf("Session ID unchanged: %s", oldID)
		return oldSession
	}

	log.Info().Msgf("Updating session from %s to %s (ListenPort=%d)", oldID, newID, newPort)

	// Check if new session already exists
	existingSession, exists := t.sessionManager.GetSession(newID)
	if exists {
		log.Info().Msgf("Merging old session %s into existing %s", oldID, newID)
		conn, hasConn := oldSession.GetConn()
		if hasConn {
			if _, existingHasConn := existingSession.GetConn(); !existingHasConn {
				existingSession.AddConn(conn)
			}
		}
		t.sessionManager.RemoveSession(oldID)
		return existingSession
	}

	// Create new session with correct port
	newSession := t.sessionManager.AddSession(newID, ip, newPort)

	// Transfer connection
	conn, hasConn := oldSession.GetConn()
	if hasConn {
		newSession.AddConn(conn)
	}

	// Remove old session
	t.sessionManager.RemoveSession(oldID)

	log.Info().Msgf("Successfully updated session from %s to %s", oldID, newID)
	return newSession
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
