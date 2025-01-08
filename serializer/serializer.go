package serializer

import (
	"bytes"
	"errors"
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
	calculatedHash := hasher.Sum(nil)

	if !bytes.Equal(calculatedHash, p.Header.Hash[:]) {
		return nil, fmt.Errorf("invalid hash")
	}

	// Get packet data (everything after the header)
	packetData := data[98:]

	// Deserialize based on packet type
	var err error
	switch p.Header.Type {
	case 0x01: // Ping
		println("Ping received")
		p.Data, err = deserializePing(packetData)
		if err != nil {
			println("HERRRRRRR")
			println(err.Error())
		}
		// pp := p.Data.(*Ping)
		// println(pp.Expiration)

	case 0x02: // Pong
		println("Pong received")
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
	// Print raw data for debugging
	fmt.Printf("Raw RLP data length: %d\n", len(data))
	fmt.Printf("Raw RLP data: %x\n", data)

	// Try decoding as raw list first
	var rawList []interface{}
	if err := rlp.DecodeBytes(data, &rawList); err != nil {
		fmt.Printf("Failed to decode as raw list: %v\n", err)
	} else {
		fmt.Printf("Decoded as raw list: %+v\n", rawList)
	}

	p := &Ping{}
	if err := rlp.DecodeBytes(data, p); err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %w", err)
	}
	return p, nil
}
func (p *Ping) DecodeRLP(s *rlp.Stream) error {
	var raw struct {
		Version    uint64        `rlp:"optional"`
		From       []interface{} `rlp:"optional"`
		To         []interface{} `rlp:"optional"`
		Expiration uint64        `rlp:"optional"`
		ENRSeq     uint64        `rlp:"optional"`
	}

	if err := s.Decode(&raw); err != nil {
		return fmt.Errorf("RLP decode error: %w", err)
	}

	// Process From endpoint
	if len(raw.From) < 3 {
		return errors.New("invalid from endpoint")
	}

	// Extract IP for From
	fromIPBytes, ok := raw.From[0].([]byte)
	if !ok {
		return errors.New("invalid from IP")
	}

	// Extract UDP port for From - handle both uint64 and []byte cases
	var fromUDPPort uint16
	switch v := raw.From[1].(type) {
	case uint64:
		fromUDPPort = uint16(v)
	case []byte:
		if len(v) != 2 {
			return errors.New("invalid from UDP port bytes length")
		}
		fromUDPPort = uint16(v[0])<<8 | uint16(v[1])
	default:
		return errors.New("invalid from UDP port type")
	}

	// Extract TCP port for From - handle both uint64 and []byte cases
	var fromTCPPort uint16
	switch v := raw.From[2].(type) {
	case uint64:
		fromTCPPort = uint16(v)
	case []byte:
		if len(v) != 2 {
			return errors.New("invalid from TCP port bytes length")
		}
		fromTCPPort = uint16(v[0])<<8 | uint16(v[1])
	default:
		return errors.New("invalid from TCP port type")
	}

	// Process To endpoint
	if len(raw.To) < 3 {
		return errors.New("invalid to endpoint")
	}

	// Extract IP for To
	toIPBytes, ok := raw.To[0].([]byte)
	if !ok {
		return errors.New("invalid to IP")
	}

	// Extract UDP port for To - handle both uint64 and []byte cases
	var toUDPPort uint16
	switch v := raw.To[1].(type) {
	case uint64:
		toUDPPort = uint16(v)
	case []byte:
		if len(v) != 2 {
			return errors.New("invalid to UDP port bytes length")
		}
		toUDPPort = uint16(v[0])<<8 | uint16(v[1])
	default:
		return errors.New("invalid to UDP port type")
	}

	// Extract TCP port for To - handle both uint64 and []byte cases, allowing empty/null
	var toTCPPort uint16
	if raw.To[2] != nil {
		switch v := raw.To[2].(type) {
		case uint64:
			toTCPPort = uint16(v)
		case []byte:
			if len(v) == 0 {
				// Empty TCP port is allowed in the spec
				toTCPPort = 0
			} else if len(v) == 2 {
				toTCPPort = uint16(v[0])<<8 | uint16(v[1])
			} else {
				return errors.New("invalid to TCP port bytes length")
			}
		default:
			return errors.New("invalid to TCP port type")
		}
	}

	// Populate the Ping structure
	p.Version = raw.Version
	p.From = Endpoint{IP: fromIPBytes, UDP: fromUDPPort, TCP: fromTCPPort}
	p.To = Endpoint{IP: toIPBytes, UDP: toUDPPort, TCP: toTCPPort}
	p.Expiration = raw.Expiration
	p.ENRSeq = raw.ENRSeq

	return nil
}
func deserializePong(data []byte) (*Pong, error) {
	// Print raw data for debugging
	fmt.Printf("Raw RLP data length: %d\n", len(data))
	fmt.Printf("Raw RLP data: %x\n", data)

	// Try decoding as raw list first
	var rawList []interface{}
	if err := rlp.DecodeBytes(data, &rawList); err != nil {
		fmt.Printf("Failed to decode as raw list: %v\n", err)
	} else {
		fmt.Printf("Decoded as raw list: %+v\n", rawList)
	}

	// Now try normal decoding
	p := &Pong{}
	if err := rlp.DecodeBytes(data, p); err != nil {
		return nil, fmt.Errorf("failed to decode RLP: %w", err)
	}
	return p, nil
}
func (p *Pong) DecodeRLP(s *rlp.Stream) error {
	var raw struct {
		To         []interface{} `rlp:"optional"`
		PingHash   []byte        `rlp:"optional"`
		Expiration uint64        `rlp:"optional"`
		ENRSeq     uint64        `rlp:"optional"`
	}

	if err := s.Decode(&raw); err != nil {
		return fmt.Errorf("RLP decode error: %w", err)
	}

	// Process To endpoint
	if len(raw.To) < 3 {
		return errors.New("invalid to endpoint")
	}

	// Extract IP
	ipBytes, ok := raw.To[0].([]byte)
	if !ok {
		return errors.New("invalid to IP")
	}

	// Extract UDP port - handle both uint64 and []byte cases
	var udpPort uint16
	switch v := raw.To[1].(type) {
	case uint64:
		udpPort = uint16(v)
	case []byte:
		// Convert 2 bytes to uint16: first byte << 8 | second byte
		if len(v) != 2 {
			return errors.New("invalid UDP port bytes length")
		}
		udpPort = uint16(v[0])<<8 | uint16(v[1])
	default:
		return errors.New("invalid UDP port type")
	}

	// Extract TCP port - handle both uint64 and []byte cases
	var tcpPort uint16
	switch v := raw.To[2].(type) {
	case uint64:
		tcpPort = uint16(v)
	case []byte:
		// Convert 2 bytes to uint16: first byte << 8 | second byte
		if len(v) != 2 {
			return errors.New("invalid TCP port bytes length")
		}
		tcpPort = uint16(v[0])<<8 | uint16(v[1])
	default:
		return errors.New("invalid TCP port type")
	}

	// Populate the Pong structure
	p.To = Endpoint{IP: ipBytes, UDP: udpPort, TCP: tcpPort}
	if len(raw.PingHash) == 32 {
		copy(p.PingHash[:], raw.PingHash)
	}
	p.Expiration = raw.Expiration
	p.ENRSeq = raw.ENRSeq

	return nil
}
