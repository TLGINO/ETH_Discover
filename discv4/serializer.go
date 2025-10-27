package discv4

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// DeserializePacket deserializes a raw packet into a Packet struct
func DeserializePacket(data []byte) (*Packet, error) {
	var p Packet
	if len(data) < 98 {
		return nil, fmt.Errorf("packet too small")
	}
	// Extract header components
	copy(p.Header.Hash[:], data[0:32])
	copy(p.Header.Signature[:], data[32:97])
	p.Header.Type = data[97]

	// Verify packet hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data[32:]) // hash everything after the hash itself

	// Get packet data (everything after the header)
	packetData := data[98:]

	var resolved_packet PacketData
	switch p.Header.Type {
	case 0x01: // Ping
		resolved_packet = &Ping{}
	case 0x02: // Pong
		resolved_packet = &Pong{}
	case 0x03: // FindNode
		resolved_packet = &FindNode{}
	case 0x04: // Neighbors
		resolved_packet = &Neighbors{}
	case 0x05: // ENRRequest
		resolved_packet = &ENRRequest{}
	case 0x06: // ENRResponse
		resolved_packet = &ENRResponse{}
	default:
		return nil, fmt.Errorf("invalid packet type: %x", p.Header.Type)
	}
	err := deserializePacket(packetData, resolved_packet)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize packet data, type: %v: %w ", p.Header.Type, err)
	}
	p.Data = resolved_packet

	return &p, nil
}

// ------------------------------------
// Deserializing

func deserializePacket(data []byte, v interface{}) error {
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(v)
	if err != nil {
		return fmt.Errorf("error deserializing: %v", err)
	}
	return nil
}
