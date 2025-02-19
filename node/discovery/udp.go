package discovery

import (
	"eth_discover/discv4"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

type UDP struct {
	conn     *net.UDPConn
	port     uint16
	registry *Registry // <- dependency injection

	messageLock sync.Mutex
}

func (u *UDP) Init(port uint16, registry *Registry) error {
	u.port = port
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
			log.Err(err).Msg("UDP read error")
			continue
		}
		go u.handleConnection(buf[:n], addr)
	}
}

func (u *UDP) handleConnection(data []byte, addr *net.UDPAddr) {
	u.messageLock.Lock()
	defer u.messageLock.Unlock()

	packet, err := discv4.DeserializePacket(data)
	if err != nil {
		log.Error().Err(err).Msg("error received udp data")
		return
	}
	u.registry.ExecCallBack(packet, addr.IP.String())
}

func (u *UDP) Send(to string, data []byte) {

	// Check if address contains more than one colon (indicating IPv6)
	if strings.Count(to, ":") > 1 {
		// Split the address and port
		lastColon := strings.LastIndex(to, ":")
		if lastColon == -1 {
			log.Error().Err(fmt.Errorf("invalid address format")).Msgf("invalid address format: %s", to)
			return
		}

		ipStr := to[:lastColon]
		portStr := to[lastColon+1:]

		// If IPv6 address isn't already wrapped in brackets, wrap it
		if !strings.HasPrefix(ipStr, "[") {
			ipStr = "[" + ipStr + "]"
		}

		// Recombine with port
		to = ipStr + ":" + portStr
	}

	addr, err := net.ResolveUDPAddr("udp", to)
	if err != nil {
		log.Error().Err(err).Msgf("error resolving UDP address: %v", addr)
		return
	}

	_, err = u.conn.WriteToUDP(data, addr)
	if err != nil {
		log.Error().Err(err).Msg("error sending via udp:")
		return
	}
}
