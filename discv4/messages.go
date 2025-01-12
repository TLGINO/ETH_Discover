package discv4

import (
	"fmt"
	"go_fun/enr"
	G "go_fun/global"
	"net"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
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

type ENode struct {
	IP  net.IP
	UDP uint16
	TCP uint16
	ID  [64]byte // secp256k1 public key
}

// -------

// implements PacketData
type Ping struct {
	Version    uint64
	From       Endpoint
	To         Endpoint
	Expiration uint64 // Unix timestamp
	ENRSeq     uint64 `rlp:"optional"` // Optional ENR sequence number

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

func (p Ping) Type() byte { return 0x01 }

// -------

// implements PacketData
type Pong struct {
	To         Endpoint // Endpoint of the original ping sender
	PingHash   [32]byte // Hash of the corresponding ping packet
	Expiration uint64   // Unix timestamp when this packet expires
	ENRSeq     uint64   `rlp:"optional"` // Optional ENR sequence number

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

func (p Pong) Type() byte { return 0x02 }

// -------

// implements PacketData
type FindNode struct {
	Target     [64]byte // secp256k1 public key
	Expiration uint64   // Unix timestamp when this packet expires

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f FindNode) Type() byte { return 0x03 }

// -------

// implements PacketData
type Neighbors struct {
	Nodes      []ENode // [[ip, udp-port, tcp-port, node-id], ...]
	Expiration uint64  // Unix timestamp when this packet expires

	Rest []rlp.RawValue `rlp:"tail"`
}

func (n Neighbors) Type() byte { return 0x04 }

// -------

// implements PacketData
type ENRRequest struct {
	Expiration uint64 // Unix timestamp when this packet expires

	Rest []rlp.RawValue `rlp:"tail"`
}

func (e ENRRequest) Type() byte { return 0x05 }

// -------

// implements PacketData
type ENRResponse struct {
	RequestHash [32]byte // Hash of the entire ENRRequest packet being replied to
	ENR         enr.ENR

	Rest []rlp.RawValue `rlp:"tail"`
}

func (e ENRResponse) Type() byte { return 0x06 }

//
// ------------------------------------
// Packet Serializing
//

// Serialize returns the serialized data of a Packet obj and an error
func (p *Packet) Serialize() ([]byte, error) {
	data, err := rlp.EncodeToBytes(p.Data)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, 98+len(data)) // Header size + Data size
	packet = append(packet, p.Header.Hash[:]...)
	packet = append(packet, p.Header.Signature[:]...)
	packet = append(packet, p.Data.Type())
	packet = append(packet, data...)

	return packet, nil
}

func NewPacket(pd PacketData) (*Packet, error) {
	data, err := rlp.EncodeToBytes(pd)
	if err != nil {
		return nil, err
	}

	to_sign := append([]byte{pd.Type()}, data...)
	sig, err := crypto.Sign(crypto.Keccak256(to_sign), G.PRIVATE_KEY)
	if err != nil {
		return nil, err
	}

	to_hash := append(sig, to_sign...)
	hash := crypto.Keccak256(to_hash)

	ph := PacketHeader{
		Hash:      [32]byte(hash),
		Signature: [65]byte(sig),
		Type:      pd.Type(),
	}

	p := Packet{
		Header: ph,
		Data:   pd,
	}

	return &p, nil
}

//
// ------------------------------------
// Creating Packets
//

func NewPingPacket(version uint64, from Endpoint, to Endpoint, expiration uint64) (*Packet, error) {
	ping := Ping{
		Version:    version,
		From:       from,
		To:         to,
		Expiration: expiration,
		ENRSeq:     0,
	}
	return NewPacket(ping)
}
func NewPongPacket(to Endpoint, hash [32]byte, expiration uint64) (*Packet, error) {
	pong := Pong{
		To:         to,
		PingHash:   hash,
		Expiration: expiration,
		ENRSeq:     0,
	}
	return NewPacket(pong)
}
func NewFindNodePacket(expiration uint64) (*Packet, error) {

	publicKeyBytes := crypto.FromECDSAPub(G.PUBLIC_KEY)
	pubBytes := crypto.Keccak256Hash(publicKeyBytes)

	var target [64]byte
	copy(target[:], pubBytes[:])

	findNode := FindNode{
		Target:     target,
		Expiration: expiration,
	}
	return NewPacket(findNode)
}
func NewENRRequestPacket(expiration uint64) (*Packet, error) {
	enrRequest := ENRRequest{
		Expiration: expiration,
	}
	return NewPacket(enrRequest)
}
func NewENRResponsePacket(hash [32]byte, enr enr.ENR) (*Packet, error) {
	enrResponse := ENRResponse{
		RequestHash: hash,
		ENR:         enr,
	}
	return NewPacket(enrResponse)
}

//
// ------------------------------------
// Printing
//

func (e Endpoint) String() string {
	return fmt.Sprintf("IP: %v, UDP: %d, TCP: %d", net.IP(e.IP), e.UDP, e.TCP)
}

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
func (f FindNode) String() string {
	return fmt.Sprintf("FindNode{\n"+
		"  Target: %x\n"+
		"  Expiration: %d\n"+
		"}",
		f.Target,
		f.Expiration,
	)
}
func (n Neighbors) String() string {
	nodesStr := ""
	for _, node := range n.Nodes {
		nodesStr += fmt.Sprintf("{IP: %v, UDP: %d, TCP: %d, ID: %x}, ", node.IP, node.UDP, node.TCP, node.ID)
	}
	return fmt.Sprintf("Neighbors{\n"+
		"  Nodes: [%v]\n"+
		"  Expiration: %d\n"+
		"}",
		nodesStr,
		n.Expiration,
	)
}
func (e ENRRequest) String() string {
	return fmt.Sprintf("ENRRequest{\n"+
		"  Expiration: %d\n"+
		"}",
		e.Expiration,
	)
}
func (e ENRResponse) String() string {
	return fmt.Sprintf("ENRResponse{\n"+
		"  RequestHash: %x\n"+
		"  ENR: %v\n"+
		"}",
		e.RequestHash,
		e.ENR,
	)
}
