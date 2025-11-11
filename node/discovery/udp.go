package discovery

import (
	"eth_discover/discv4"
	"eth_discover/interfaces"
	"fmt"
	"net"

	"github.com/rs/zerolog/log"
)

type UDP struct {
	conn     *net.UDPConn
	port     uint16
	registry *Registry      // <- dependency injection
	dn       *DiscoveryNode // <- dependency injection
}

func (u *UDP) Init(port uint16, registry *Registry, dn *DiscoveryNode) error {
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
	u.dn = dn

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
	packet, err := discv4.DeserializePacket(data)
	if err != nil {
		log.Error().Err(err).Msg("error received udp data")

		// Maybe the error was due to discv5
		// In which case, attempt to initialize connection using discv4
		// To do this, add node such that it will get picked up by the bonding process
		enode := interfaces.ENode{
			IP:  addr.IP,
			UDP: uint16(addr.Port),
			TCP: 0,
		}
		u.dn.AddENode(&enode)

		return
	}

	nodeAddr := interfaces.NodeAddress{
		IP:   addr.IP,
		Port: addr.Port,
	}
	u.registry.ExecCallBack(packet, nodeAddr)
}

func (u *UDP) Send(to string, data []byte) {

	host, port, err := net.SplitHostPort(to)
	if err != nil {
		log.Error().Err(err).Msgf("invalid address format: %s", to)
		return
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
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
