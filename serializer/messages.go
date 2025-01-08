package serializer

import (
	"crypto/ecdsa"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
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
	Type() byte
	String() string
}

type Endpoint struct {
	IP  net.IP
	UDP uint16
	TCP uint16
}

func (e Endpoint) String() string {
	return fmt.Sprintf("IP: %v, UDP: %d, TCP: %d", net.IP(e.IP), e.UDP, e.TCP)
}

// implements PacketData
type Ping struct {
	Version    uint64
	From       Endpoint
	To         Endpoint
	Expiration uint64 // Unix timestamp
	ENRSeq     uint64 // Optional ENR sequence number
}

func (p Ping) Type() byte { return 0x01 }

func (p Ping) String() string {
	return fmt.Sprintf("Ping{\n"+
		"  Version: %d\n"+
		"  From: {%v}\n"+
		"  To: {%v}\n"+
		"  Expiration: %d\n"+
		"  ENRSeq: %d\n"+
		"}",
		p.Version,
		p.From,
		p.To,
		p.Expiration,
		p.ENRSeq,
	)
}

type Pong struct {
	To         Endpoint // Endpoint of the original ping sender
	PingHash   [32]byte // Hash of the corresponding ping packet
	Expiration uint64   // Unix timestamp when this packet expires
	ENRSeq     uint64   // Optional ENR sequence number
}

func (p Pong) Type() byte { return 0x02 }

func (p Pong) String() string {
	return fmt.Sprintf("Pong{\n"+
		"  To: {%v}\n"+
		"  PingHash: %x\n"+
		"  Expiration: %d\n"+
		"  ENRSeq: %d\n"+
		"}",
		p.To,
		p.PingHash,
		p.Expiration,
		p.ENRSeq,
	)
}
func Serialize(pd PacketData, priv *ecdsa.PrivateKey) ([]byte, error) {
	// 1. RLP encode the packet data
	encodedData, err := rlp.EncodeToBytes(pd)
	if err != nil {
		return nil, err
	}

	// 2. Create the packet to be signed: packet-type || packet-data
	toSign := append([]byte{pd.Type()}, encodedData...)

	// 3. Sign the packet
	hash := crypto.Keccak256(toSign)
	signature, err := crypto.Sign(hash, priv)
	if err != nil {
		return nil, err
	}

	// 4. Assemble the final packet: hash || signature || packet-type || packet-data
	packet := make([]byte, 0, len(hash)+len(signature)+1+len(encodedData))

	// Calculate hash of the signed data
	finalHash := sha3.NewLegacyKeccak256()
	finalHash.Write(signature)
	finalHash.Write([]byte{pd.Type()})
	finalHash.Write(encodedData)

	packet = append(packet, finalHash.Sum(nil)...)
	packet = append(packet, signature...)
	packet = append(packet, pd.Type())
	packet = append(packet, encodedData...)

	return packet, nil
}
func NewPing(version uint64, from Endpoint, to Endpoint, expiration uint64, priv *ecdsa.PrivateKey) ([]byte, error) {
	ping := Ping{
		Version:    version,
		From:       from,
		To:         to,
		Expiration: expiration,
		// ENRSeq:     enrSeq,
	}
	return Serialize(ping, priv)
}
