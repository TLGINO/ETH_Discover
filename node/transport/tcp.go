package transport

import (
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Define timeouts to prevent freezing
const (
	ReadDeadline  = 30 * time.Second
	WriteDeadline = 10 * time.Second
	DialTimeout   = 5 * time.Second
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
	session_id := ip + ":" + portStr
	defer func() {
		t.sessionManager.RemoveSession(session_id)
		conn.Close()
	}()

	// if new session, add it
	sess, found := t.sessionManager.GetSession(session_id)
	if !found {
		portInt, _ := strconv.Atoi(portStr)
		sess = t.sessionManager.AddSession(session_id, net.ParseIP(ip), uint16(portInt))
	}
	sess.AddConn(conn)
	for {
		// Set a ReadDeadline to ensure we don't block forever if the peer goes silent
		if err := conn.SetReadDeadline(time.Now().Add(ReadDeadline)); err != nil {
			log.Error().Err(err).Msgf("failed to set read deadline for %v", ip)
			return
		}

		// deserialize message
		packet, pType, err := rlpx.DeserializePacket(conn, sess, found)
		if err != nil {
			if err == io.EOF {
				log.Warn().Msgf("connection closed by remote %v", ip)
				return
			}

			// Handle specific network errors like timeouts or closed connections
			if opErr, ok := err.(*net.OpError); ok {
				if opErr.Timeout() {
					log.Warn().Msgf("connection read timed out %v", ip)
					return
				}
				if opErr.Err.Error() == "use of closed network connection" {
					log.Warn().Msgf("connection closed: use of closed network connection %v", ip)
					return
				}
			}

			log.Error().Err(err).Msgf("error received tcp data %v", ip)
			// Not too sure whether to disconnect or not here
			// t.sessionManager.RemoveSession(ip)
			// return
			continue
		}

		// exec callback
		t.registry.ExecCallBack(packet, pType, sess)
	}
}

func (t *TCP) Send(sess *session.Session, data []byte) {
	// Check if we already have a connection to this address
	conn, found := sess.GetConn()

	if !found {
		toIP, toPort := sess.To()
		to := net.JoinHostPort(toIP.String(), strconv.Itoa(int(toPort)))

		// open connection with a timeout
		dialer := net.Dialer{Timeout: DialTimeout}
		newConn, err := dialer.Dial("tcp", to)
		if err != nil {
			log.Error().Err(err).Msgf("failed to connect to server")
			t.Close(sess)
			return
		}

		// add conn to session
		sess.AddConn(newConn)

		// listen on connection
		go t.handleConnection(newConn)

		// always get the connection from session after adding
		conn, _ = sess.GetConn()
	}

	// Set a WriteDeadline to prevent blocking if the peer isn't reading
	if err := conn.SetWriteDeadline(time.Now().Add(WriteDeadline)); err != nil {
		log.Error().Err(err).Msg("failed to set write deadline")
		t.Close(sess)
		return
	}

	// Send data using the connection
	_, err := conn.Write(data)
	if err != nil {
		// Remove failed connection
		log.Error().Err(err).Msg("error sending via tcp:")
		t.Close(sess)
		return
	}
}

func (t *TCP) Close(sess *session.Session) {
	// Close the connection without sending disconnect
	// To close and disconnect, see transport_node.go
	conn, found := sess.GetConn()

	if found {
		conn.Close()
	}

	// remove from session manager
	// do not re-use conn object here -> potentially nil
	session_id := sess.GetID()
	t.sessionManager.RemoveSession(session_id)

	// find enode to reset
	_, nodeID := sess.GetNodeID()
	allENodeTuples := t.tn.node.GetAllENodes()
	for _, enode := range allENodeTuples {
		if enode.Enode.ID == nodeID {
			t.tn.node.UpdateENode(&enode.Enode, interfaces.NotBondedENode)
			return
		}
	}
}
