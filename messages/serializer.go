package messages

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// DeserializePacket deserializes a raw packet into a Packet struct
func DeserializePacket(data []byte) (*Packet, error) {
	var p Packet

	// Extract header components
	copy(p.Header.Hash[:], data[0:32])
	copy(p.Header.Signature[:], data[32:97])
	p.Header.Type = data[97]

	// Verify packet hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data[32:]) // hash everything after the hash itself

	// Get packet data (everything after the header)
	packetData := data[98:]

	var err error
	switch p.Header.Type {
	case 0x01: // Ping
		p.Data, err = deserializePing(packetData)
	case 0x02: // Pong
		p.Data, err = deserializePong(packetData)
	default:
		return nil, fmt.Errorf("invalid packet type: %x", p.Header.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize packet data: %w", err)
	}

	return &p, nil
}

func deserializePing(data []byte) (*Ping, error) {
	var m Ping
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing ping: " + err.Error())
	}
	return &m, nil
}
func deserializePong(data []byte) (*Pong, error) {
	var m Pong
	stream := rlp.NewStream(bytes.NewReader(data), 0)
	err := stream.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("error deserializing pong: " + err.Error())
	}
	return &m, nil
}