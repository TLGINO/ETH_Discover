package discovery

import (
	"eth_discover/discv4"
	"eth_discover/enr"
	"eth_discover/interfaces"
	"time"

	"github.com/rs/zerolog/log"
)

func (dn *DiscoveryNode) ExecPing(m discv4.Packet, from interfaces.NodeAddress) {
	ping := m.Data.(*discv4.Ping)
	log.Info().Str("component", "discv4").Msg("received Ping")

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())
	_, pongData, err := discv4.NewPongPacket(ping.From, m.Header.Hash[:], expiration)
	if err != nil {
		log.Err(err).Str("component", "discv4").Msg("error creating Pong")
		return
	}

	dn.SendUDP(ping.From.IP, ping.From.UDP, pongData)
}

func (dn *DiscoveryNode) ExecPong(m discv4.Packet, from interfaces.NodeAddress) {
	pong := m.Data.(*discv4.Pong)
	log.Info().Str("component", "discv4").Msg("received Pong")

	var pingHashArr [32]byte
	copy(pingHashArr[:], pong.PingHash)
	ch := dn.GetAwaitPong(pingHashArr)
	if ch != nil {
		ch <- struct{}{}
	} else {
		log.Info().Str("component", "discv4").Msg("unsolicited or delayed Pong received")
	}
}
func (dn *DiscoveryNode) ExecFindNode(m discv4.Packet, from interfaces.NodeAddress) {
	findNode := m.Data.(*discv4.FindNode)
	log.Info().Str("component", "discv4").Msgf("received findNode: %s", findNode)
	// [TODO] respond

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())
	_, neighborsData, err := discv4.NewNeighborsPacket(expiration)
	if err != nil {
		log.Err(err).Str("component", "discv4").Msg("error creating Neighbors")
		return
	}
	dn.SendUDP(from.IP, uint16(from.Port), neighborsData)

}
func (dn *DiscoveryNode) ExecNeighbors(m discv4.Packet, from interfaces.NodeAddress) {
	neighbors := m.Data.(*discv4.Neighbors)
	log.Info().Str("component", "discv4").Msgf("received neighbours: %d", len(neighbors.Nodes))

	for _, enode := range neighbors.Nodes {
		dn.AddENode(&enode)
	}

	ch := dn.GetAwaitNeighbours(from.IP.String())
	if ch != nil {
		select {
		case ch <- struct{}{}:
			// Successfully sent
		default:
			log.Info().Str("component", "discv4").Msgf("channel full or closed for neighbour response from %s", from.IP)
		}
	} else {
		log.Info().Str("component", "discv4").Msgf("unsolicited or delayed neighbour message received from %s", from.IP)
	}
}
func (dn *DiscoveryNode) ExecENRRequest(m discv4.Packet, from interfaces.NodeAddress) {
	enrRequest := m.Data.(*discv4.ENRRequest)
	log.Info().Str("component", "discv4").Msgf("received enrRequest: %s", enrRequest)
	enrData := enr.GetENR()
	_, enrData, err := discv4.NewENRResponsePacket(m.Header.Hash[:32], enrData)
	if err != nil {
		log.Err(err).Str("component", "discv4").Msg("error creating ENRResponse")
		return
	}
	dn.SendUDP(from.IP, uint16(from.Port), enrData)
}
func (dn *DiscoveryNode) ExecENRResponse(m discv4.Packet, from interfaces.NodeAddress) {
	enrResponse := m.Data.(*discv4.ENRResponse)
	log.Info().Str("component", "discv4").Msgf("received enrResponse: %s", enrResponse)
}
