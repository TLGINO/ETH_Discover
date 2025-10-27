package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

type TCP struct {
	listener       net.Listener
	port           uint16
	sessionManager *session.SessionManager
	registry       *Registry // <- dependency injection

}

func (t *TCP) Init(port uint16, registry *Registry, sessionManager *session.SessionManager) error {
	t.port = port
	addr := fmt.Sprintf(":%d", t.port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("error creating TCP server: %v", err)
	}
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

		go t.handleConnection(conn)
	}
}

func (t *TCP) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)
	defer func() {
		t.sessionManager.RemoveSession(ip)
		conn.Close()
	}()

	for {
		// if new session, add it
		session, found := t.sessionManager.GetSession(ip)
		if !found {
			session = t.sessionManager.AddSession(net.ParseIP(ip), uint16(conn.RemoteAddr().(*net.TCPAddr).Port))
		}
		session.AddConn(conn)

		// read from connection
		// err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		// if err != nil {
		// 	log.Error().Err(err).Msg("error setting read deadline")
		// 	return
		// }

		// deserialize message
		packet, pType, err := rlpx.DeserializePacket(conn, session, found)
		if err != nil {
			if err == io.EOF {
				log.Warn().Msg("connection closed by remote")
				return
			}

			// Handle specific network errors like "use of closed network connection"
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				log.Warn().Msg("connection closed: use of closed network connection")
				return
			}

			log.Error().Err(err).Msg("error received tcp data")
			// Not too sure whether to disconnect or not here
			// t.sessionManager.RemoveSession(ip)
			// return
			continue
		}

		// exec callback
		t.registry.ExecCallBack(packet, pType, session)
	}
}

func (t *TCP) Send(session *session.Session, data []byte) {
	// Check if we already have a connection to this address
	conn, found := session.GetConn()

	if !found {
		// create address ipv4 / ipv6
		toIP, toPort := session.To()
		var to string
		if toIP.To4() != nil {
			to = toIP.String() + ":" + strconv.Itoa(int(toPort))
		} else {
			to = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
		}

		// open connection
		newConn, err := net.DialTimeout("tcp", to, 1*time.Second)
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
	toIP, toPort := session.To()
	var to string
	if toIP.To4() != nil {
		to = toIP.String() + ":" + strconv.Itoa(int(toPort))
	} else {
		to = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
	}
	t.sessionManager.RemoveSession(to)
}
