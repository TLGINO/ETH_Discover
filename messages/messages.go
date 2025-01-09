package messages

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

// total 98 bytes
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

// Serialize returns the serialized data of a Packet obj and an error
func (p *Packet) Serialize() ([]byte, error) {
	// 1. RLP encode the packet data
	encodedData, err := rlp.EncodeToBytes(p.Data)
	if err != nil {
		return nil, err
	}

	hash := p.Header.Hash
	signature := p.Header.Signature
	dtype := p.Header.Type

	// 4. Assemble the final packet: hash || signature || packet-type || packet-data
	data := make([]byte, 0, len(hash)+len(signature)+1+len(encodedData))

	data = append(data, hash[:]...)
	data = append(data, signature[:]...)
	data = append(data, dtype)
	data = append(data, encodedData...)

	return data, nil
}
func NewPacket(pd PacketData, priv *ecdsa.PrivateKey) (*Packet, error) {
	// get RLP encoded data
	encodedData, err := rlp.EncodeToBytes(pd)
	if err != nil {
		return nil, err
	}

	// create signature
	hasherSignature := sha3.NewLegacyKeccak256()
	hasherSignature.Write([]byte{pd.Type()})
	signature, err := crypto.Sign(hasherSignature.Sum(nil), priv)
	if err != nil {
		return nil, err
	}

	// create hash
	hashPacket := sha3.NewLegacyKeccak256()
	hashPacket.Write(signature[:])
	hashPacket.Write([]byte{pd.Type()})
	hashPacket.Write(encodedData)
	ph := PacketHeader{
		Hash:      [32]byte(hashPacket.Sum(nil)),
		Signature: [65]byte(signature),
		Type:      pd.Type(),
	}
	p := Packet{
		Header: ph,
		Data:   pd,
	}
	return &p, nil

}

func NewPingPacket(version uint64, from Endpoint, to Endpoint, expiration uint64, priv *ecdsa.PrivateKey) (*Packet, error) {
	ping := Ping{
		Version:    version,
		From:       from,
		To:         to,
		Expiration: expiration,
		// ENRSeq:     enrSeq,
	}
	return NewPacket(ping, priv)
}
