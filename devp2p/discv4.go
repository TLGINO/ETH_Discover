package devp2p

import (
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// Packet is the base structure for all discovery packets
type Packet struct {
	Header PacketHeader
	Data   PacketData
}

// PacketHeader contains the common header fields for all packets
type PacketHeader struct {
	Hash      [32]byte // keccak256 hash
	Signature [65]byte // r[32] || s[32] || v[1]
	Type      byte     // packet type identifier
}

// PacketData is the interface that all packet types must implement
type PacketData interface {
	Type() byte
}

// Ping packet (0x01)
type Ping struct {
	Version    uint
	From       Endpoint
	To         Endpoint
	Expiration uint64 // Unix timestamp
	ENRSeq     uint64 // Optional ENR sequence number
}

func (p Ping) Type() byte { return 0x01 }

// Pong packet (0x02)
type Pong struct {
	To         Endpoint
	PingHash   [32]byte // Hash of the corresponding ping
	Expiration uint64   // Unix timestamp
	ENRSeq     uint64   // Optional ENR sequence number
}

func (p Pong) Type() byte { return 0x02 }

// Endpoint represents network location information
type Endpoint struct {
	IP  net.IP
	UDP uint16
	TCP uint16
}

// Constants
const (
	MaxPacketSize   = 1280           // Maximum size of discovery packets
	BucketSize      = 16             // Size of each k-bucket (k=16)
	Alpha           = 3              // Concurrency parameter for recursive lookup
	ProofExpiration = 12 * time.Hour // Endpoint proof expiration time
)

// EncodePacket encodes and signs a packet
func EncodePacket(priv *ecdsa.PrivateKey, ptype byte, data interface{}) ([]byte, error) {
	// 1. RLP encode the packet data
	encodedData, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, err
	}

	// 2. Create the packet to be signed: packet-type || packet-data
	toSign := append([]byte{ptype}, encodedData...)

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
	finalHash.Write([]byte{ptype})
	finalHash.Write(encodedData)

	packet = append(packet, finalHash.Sum(nil)...)
	packet = append(packet, signature...)
	packet = append(packet, ptype)
	packet = append(packet, encodedData...)

	return packet, nil
}

var MainnetBootnodes = []string{
	"enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303",
	"enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303",
	"enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303",
	"enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303",
}
