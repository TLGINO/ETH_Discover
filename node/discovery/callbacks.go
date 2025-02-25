package discovery

import (
	"eth_discover/discv4"
	"time"

	"github.com/rs/zerolog/log"
)

func (dn *DiscoveryNode) ExecPing(m discv4.Packet, from string) {
	ping := m.Data.(*discv4.Ping)
	log.Info().Str("component", "discv4").Msg("received Ping")

	expiration := uint64(time.Now().Add(50 * time.Second).Unix())
	_, pongData, err := discv4.NewPongPacket(ping.From, m.Header.Hash, expiration)
	if err != nil {
		log.Err(err).Str("component", "discv4").Msg("error creating Pong")
		return
	}

	dn.SendUDP(ping.From.IP, ping.From.UDP, pongData)
}

func (dn *DiscoveryNode) ExecPong(m discv4.Packet, from string) {
	pong := m.Data.(*discv4.Pong)
	log.Info().Str("component", "discv4").Msg("received Pong")

	ch := dn.GetAwaitPong(pong.PingHash)
	if ch != nil {
		ch <- struct{}{}
	} else {
		log.Info().Str("component", "discv4").Msg("unsolicited or delayed Pong received")
	}
}
func (dn *DiscoveryNode) ExecFindNode(m discv4.Packet, from string) {
	findNode := m.Data.(*discv4.FindNode)
	log.Info().Str("component", "discv4").Msgf("received findNode: %s", findNode)
	// [TODO] respond
}
func (dn *DiscoveryNode) ExecNeighbors(m discv4.Packet, from string) {
	neighbors := m.Data.(*discv4.Neighbors)
	log.Info().Str("component", "discv4").Msgf("received neighbours: %d", len(neighbors.Nodes))

	for _, enode := range neighbors.Nodes {
		dn.AddENode(&enode)
	}

	ch := dn.GetAwaitNeighbours(from)
	if ch != nil {
		select {
		case ch <- struct{}{}:
			// Successfully sent
		default:
			log.Info().Str("component", "discv4").Msgf("channel full or closed for neighbour response from %s", from)
		}
	} else {
		log.Info().Str("component", "discv4").Msgf("unsolicited or delayed neighbour message received from %s", from)
	}
}
func (dn *DiscoveryNode) ExecENRRequest(m discv4.Packet, from string) {
	enrRequest := m.Data.(*discv4.ENRRequest)
	log.Info().Str("component", "discv4").Msgf("received enrRequest: %s", enrRequest)

	// [TODO] respond
}
func (dn *DiscoveryNode) ExecENRResponse(m discv4.Packet, from string) {
	enrResponse := m.Data.(*discv4.ENRResponse)
	log.Info().Str("component", "discv4").Msgf("received enrResponse: %s", enrResponse)
}
