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

		go t.handleConnection(conn)
	}
}
func (t *TCP) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	ip, portStr, _ := net.SplitHostPort(remoteAddr)

	// WARNING: This ID is unstable for incoming connections (ephemeral port).
	// Better to rely on NodeID once handshake completes.
	session_id := ip + ":" + portStr

	defer func() {
		t.sessionManager.RemoveSession(session_id)
		conn.Close()
	}()

	session, found := t.sessionManager.GetSession(session_id)
	if !found {
		portInt, _ := strconv.Atoi(portStr)
		session = t.sessionManager.AddSession(session_id, net.ParseIP(ip), uint16(portInt))
	}
	session.AddConn(conn)

	// FIX #1: Track handshake state locally if session isn't trustworthy yet
	handshakeStarted := found

	for {
		// FIX #1: Pass the updated state, not the initial variable
		packet, pType, err := rlpx.DeserializePacket(conn, session, handshakeStarted)

		// Once we successfully read a packet, we know the session exists/handshake is moving
		if err == nil {
			handshakeStarted = true
		}

		if err != nil {
			if err == io.EOF {
				log.Warn().Msgf("connection closed by remote %v", ip)
				return
			}
			// Handle specific "use of closed network connection" error
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}

			log.Error().Err(err).Msgf("read error from %v", ip)
			continue
			// return // FIX: Return on error to break infinite error loops
		}

		// FIX #3: Ensure this callback is FAST.
		// If it makes HTTP calls (like your CreateStatusMessage), it WILL timeout the peer.
		t.registry.ExecCallBack(packet, pType, session)
	}
}

func (t *TCP) Send(session *session.Session, data []byte) {
	// Check if we already have a connection to this address
	conn, found := session.GetConn()

	if !found {
		toIP, toPort := session.To()
		to := net.JoinHostPort(toIP.String(), strconv.Itoa(int(toPort)))

		// open connection
		newConn, err := net.Dial("tcp", to)
		if err != nil {
			log.Error().Err(err).Msgf("failed to connect to server")
			t.Close(session)
			return
		}

		// add conn to session
		session.AddConn(newConn)

		// listen on connection
		go t.handleConnection(newConn)

		// always get the connection from session after adding
		conn, _ = session.GetConn()
	}

	// Send data using the connection
	_, err := conn.Write(data)
	if err != nil {
		// Remove failed connection
		log.Error().Err(err).Msg("error sending via tcp:")
		t.Close(session)
		return
	}
}

func (t *TCP) Close(session *session.Session) {
	// Close the connection without sending disconnect
	// To close and disconnect, see transport_node.go
	conn, found := session.GetConn()

	if found {
		conn.Close()
	}

	// remove from session manager
	// do not re-use conn object here -> potentially nil
	session_id := session.GetID()
	t.sessionManager.RemoveSession(session_id)

	// find enode to reset
	_, nodeID := session.GetNodeID()
	allENodeTuples := t.tn.node.GetAllENodes()
	for _, enode := range allENodeTuples {
		if enode.Enode.ID == nodeID {
			t.tn.node.UpdateENode(&enode.Enode, interfaces.NotBondedENode)
			return
		}
	}

}
