package serializer

import (
	"fmt"
	"net"

	"golang.org/x/crypto/sha3"
)

type Packet struct {
	Header PacketHeader
	Data   PacketData
}
type PacketHeader struct {
	Hash      [32]byte
	Signature [65]byte
	Type      byte
}
type PacketData interface {
	Serialize() ([]byte, error)
	Type() byte
}

type Endpoint struct {
	IP  net.IP
	UDP uint16
	TCP uint16
}

// implements PacketData
type Ping struct {
	Version    uint
	From       Endpoint
	To         Endpoint
	Expiration uint64 // Unix timestamp
	ENRSeq     uint64 // Optional ENR sequence number
}

func (p Ping) Type() byte { return 0x01 }

func NewPing(version uint, expiration uint64, enrSeq uint64, from, to Endpoint) Packet {
	return Packet{
		Header: PacketHeader{
			// Hash will be computed later
			// Signature will be added later
			Type: 0x01, // Ping type
		},
		Data: Ping{
			Version:    version,
			From:       from,
			To:         to,
			Expiration: expiration,
			ENRSeq:     enrSeq,
		},
	}
}
func (p *Packet) ComputeHash() error {
	// Get the packet data bytes first
	dataBytes, err := p.Data.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize packet data: %w", err)
	}

	// Create buffer for signature || type || data
	buf := make([]byte, 65+1+len(dataBytes))

	// Copy signature
	copy(buf[0:65], p.Header.Signature[:])

	// Copy type
	buf[65] = p.Data.Type()

	// Copy data
	copy(buf[66:], dataBytes)

	// Calculate hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(buf)

	// Copy hash to header
	hashBytes := hash.Sum(nil)
	copy(p.Header.Hash[:], hashBytes)

	return nil
}
