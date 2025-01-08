package serializer

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
)

func (h PacketHeader) Serialize() ([]byte, error) {
	// Direct concatenation of fixed-size fields as specified
	buf := make([]byte, 32+65+1) // hash[32] || signature[65] || type[1]

	// Copy hash
	copy(buf[0:32], h.Hash[:])

	// Copy signature
	copy(buf[32:97], h.Signature[:])

	// Set packet type
	buf[97] = h.Type

	return buf, nil
}

func (p Packet) Serialize() ([]byte, error) {
	// Serialize header
	headerBytes, err := p.Header.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Serialize packet data
	dataBytes, err := p.Data.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize packet data: %w", err)
	}

	// Concatenate header and data
	buf := make([]byte, len(headerBytes)+len(dataBytes))
	copy(buf[0:], headerBytes)
	copy(buf[len(headerBytes):], dataBytes)

	return buf, nil
}
func (p Ping) Serialize() ([]byte, error) {
	fromList := []interface{}{
		p.From.IP.To4(),
		p.From.UDP,
		p.From.TCP,
	}

	toList := []interface{}{
		p.To.IP.To4(),
		p.To.UDP,
		uint16(0), // Per spec, recipient TCP port is always 0
	}

	rlpData := []interface{}{
		p.Version,
		fromList,
		toList,
		p.Expiration,
	}

	if p.ENRSeq > 0 {
		rlpData = append(rlpData, p.ENRSeq)
	}

	return rlp.EncodeToBytes(rlpData)
}
