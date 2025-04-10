package rlpx

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	G "eth_discover/global"
	"eth_discover/session"
	"fmt"
	"math/big"
	mrand "math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

// credits to go_ethereum rlpx implementation for a lot of this logic

const (
	sskLen = 16                     // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = crypto.SignatureLength // elliptic S256
	pubLen = 64                     // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32                     // hash length (for nonce etc)

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */
)

type Packet interface{}

type AuthMessage struct {
	Signature   [sigLen]byte
	InitiatorPK [pubLen]byte
	Nonce       [shaLen]byte
	AuthVSN     uint

	Rest []rlp.RawValue `rlp:"tail"`
}

type AuthAck struct {
	RecipientEphemeralKey [pubLen]byte
	Nonce                 [shaLen]byte
	AuthVSN               uint

	Rest []rlp.RawValue `rlp:"tail"`
}

type FrameContent interface {
	Type() uint64
}

//
// ------------------------------------
// RLPX
//

type Cap struct {
	Name    string
	Version uint
}

// implements FrameContent
type FrameHello struct {
	ProtocolVersion uint64 // 5
	ClientID        string // Specifies the client software identity, as a human-readable string (e.g. "Ethereum(++)/1.0.0").
	Capabilities    []Cap
	ListenPort      uint64   // ignore
	NodeID          [64]byte // secp256k1 public key

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f FrameHello) Type() uint64 { return 0 }

// -------

// implements FrameContent
type FrameDisconnect struct {
	Reason uint64

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f FrameDisconnect) Type() uint64 { return 1 }

// -------

// implements FrameContent
type FramePing struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

func (f FramePing) Type() uint64 { return 2 }

// -------

// implements FrameContent
type FramePong struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

func (f FramePong) Type() uint64 { return 3 }

//
// ------------------------------------
// ETH
//

// https://eips.ethereum.org/EIPS/eip-2124
type ForkID struct {
	Hash [4]byte // CRC32 checksum of the genesis block and passed fork block numbers
	Next uint64  // block num of next fork
}

// implements FrameContent
type Status struct {
	Version         uint32
	NetworkID       uint64
	TotalDifficulty *big.Int
	BlockHash       [shaLen]byte
	Genesis         [shaLen]byte
	ForkID          ForkID

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f Status) Type() uint64 { return 0x10 }

// -------

type HashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

// implements FrameContent
type GetBlockHeadersRequest struct {
	Origin  HashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
}

type GetBlockHeaders struct {
	RequestId uint64
	*GetBlockHeadersRequest
}

func (f GetBlockHeaders) Type() uint64 { return 0x19 }

// -------

// implements FrameContent
type GetBlockBodies struct {
	RequestID   uint64
	BlockHashes [][shaLen]byte

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f GetBlockBodies) Type() uint64 { return 0x15 }

// -------

type BBody struct {
	Transactions []*types.Transaction // Transactions contained within a block
	Uncles       []*types.Header      // Uncles contained within a block
	Withdrawals  []*types.Withdrawal  `rlp:"optional"` // Withdrawals contained within a block
}

// implements FrameContent
type BlockBodies struct {
	RequestID uint64
	BBodies   []*BBody

	Rest []rlp.RawValue `rlp:"tail"`
}

func (f BlockBodies) Type() uint64 { return 0x16 }

// -------

// implements FrameContent
type NewBlockPacket struct {
	Block *types.Block
	TD    *big.Int
}

func (f NewBlockPacket) Type() uint64 { return 0x24 }

//
// ------------------------------------
// Creating Packets
//

func CreateAuthMessage(session *session.Session, recipientPK *ecdsa.PublicKey) ([]byte, error) {
	initNonce := make([]byte, shaLen)
	_, err := rand.Read(initNonce)
	if err != nil {
		return nil, fmt.Errorf("error generating random num: %v", err)
	}
	session.SetInitNonce(initNonce)

	// Generate ephemeral private key
	ephemeralPrivateKey, err := GenerateRandomEphemeralPrivateKey()
	if err != nil {
		return nil, err
	}
	session.SetEphemeralPrivateKey(ephemeralPrivateKey)

	// Sign known message: static-shared-secret ^ nonce
	token, err := ecies.ImportECDSA(G.PRIVATE_KEY).GenerateShared(ecies.ImportECDSAPublic(recipientPK), sskLen, sskLen)
	if err != nil {
		return nil, fmt.Errorf("error importing key: %v", err)
	}

	// XOR
	signed := xor(token, initNonce)
	signature, err := crypto.Sign(signed, ephemeralPrivateKey.ExportECDSA())
	if err != nil {
		return nil, fmt.Errorf("error signing message: %v", err)
	}

	// Save data
	initiatorPK := crypto.FromECDSAPub(G.PUBLIC_KEY)[1:]
	authMessage := AuthMessage{
		Signature:   [65]byte(signature),
		InitiatorPK: [64]byte(initiatorPK),
		Nonce:       [32]byte(initNonce),
		AuthVSN:     4,
	}

	// encrypt data
	data, err := createAuth(authMessage, recipientPK)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %v", err)
	}

	// save to session
	session.AddAuth(data)

	return data, nil
}

func CreateAuthAck(session *session.Session, initiatorPK *ecdsa.PublicKey) ([]byte, error) {
	// Get the public key bytes from the ephemeral key
	ephemeralPubKey := crypto.FromECDSAPub(session.GetEphemeralPrivateKey().PublicKey.ExportECDSA())[1:]

	// Create the auth ack message
	_, recNonce := session.GetNonces()
	authAck := AuthAck{
		RecipientEphemeralKey: [pubLen]byte(ephemeralPubKey),
		Nonce:                 [shaLen]byte(recNonce),
		AuthVSN:               4,
	}

	// Encrypt the auth ack message
	data, err := createAuth(authAck, initiatorPK)
	if err != nil {
		return nil, fmt.Errorf("error creating auth ack: %v", err)
	}

	return data, nil
}

func createAuth(authPacketBody Packet, recipientPK *ecdsa.PublicKey) ([]byte, error) {
	wbuf, err := rlp.EncodeToBytes(authPacketBody)
	if err != nil {
		return nil, err
	}
	// Pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
	wbuf = append(wbuf, make([]byte, mrand.Intn(100)+100)...)

	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(wbuf)+eciesOverhead))

	enc, err := ecies.Encrypt(rand.Reader, ecies.ImportECDSAPublic(recipientPK), wbuf, nil, prefix)
	return append(prefix, enc...), err
}

// ------------------------------------
// Frame

func CreateFrameHello(session *session.Session) ([]byte, error) {
	publicKeyBytes := crypto.FromECDSAPub(G.PUBLIC_KEY)[1:]
	cap := Cap{
		Name:    "eth",
		Version: 68,
	}
	fh := FrameHello{
		ProtocolVersion: 5,
		ClientID:        "linkedin.com/in/martin-lettry/", // Don't mind me, just plugging my linkedin
		Capabilities:    []Cap{cap},
		ListenPort:      0,
		NodeID:          [64]byte(publicKeyBytes),
	}
	f, err := createFrame(session, fh)
	if err != nil {
		return nil, fmt.Errorf("error creating hello frame: %v", err)
	}
	return f, nil
}

func CreateFramePing(session *session.Session) ([]byte, error) {
	fp := FramePing{}
	f, err := createFrame(session, fp)
	if err != nil {
		return nil, fmt.Errorf("error creating ping frame: %v", err)
	}
	return f, nil
}

func CreateFramePong(session *session.Session) ([]byte, error) {
	fp := FramePong{}
	f, err := createFrame(session, fp)
	if err != nil {
		return nil, fmt.Errorf("error creating pong frame: %v", err)
	}
	return f, nil
}

func CreateStatusMessage(session *session.Session) ([]byte, error) {

	genesis, err := HexToBytes("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	if err != nil {
		return nil, fmt.Errorf("error creating hex bytes block: %v", err)
	}

	// This is ~current
	// hexBlockHash, err := HexToBytes("a8e6390f684942d68a1cb8b6ed381131ab7eaa83b4b4d900cec76dfb52569412")
	// if err != nil {
	// 	return nil, fmt.Errorf("error creating hex bytes block: %v", err)
	// }
	// s := Status{
	// 	Version:         68,
	// 	NetworkID:       1,             // 1 for Mainnet
	// 	TotalDifficulty: big.NewInt(0), // 0 I think
	// 	BlockHash:       [shaLen]byte(hexBlockHash),
	// 	Genesis:         [shaLen]byte(genesis),
	// 	ForkID: ForkID{
	// 		Hash: [4]byte{0x9f, 0x3d, 0x22, 0x54},
	// 		Next: 0,
	// 	},
	// }

	// This is perfect for sync
	s := Status{
		Version:         68,
		NetworkID:       1,                       // 1 for Mainnet
		TotalDifficulty: big.NewInt(17179869184), // 0 I think
		BlockHash:       [shaLen]byte(genesis),
		Genesis:         [shaLen]byte(genesis),
		ForkID: ForkID{
			Hash: [4]byte{0xfc, 0x64, 0xec, 0x04},
			Next: 1150000,
		},
	}

	f, err := createFrame(session, s)
	if err != nil {
		return nil, fmt.Errorf("error creating status frame: %v", err)
	}

	return f, nil
}
func CreateFrameGetBlockHeaders(session *session.Session) ([]byte, error) {
	gbh := GetBlockHeaders{
		RequestId: 18034466903846788292,
		GetBlockHeadersRequest: &GetBlockHeadersRequest{
			Origin:  HashOrNumber{common.Hash{}, 22189093},
			Amount:  512,
			Skip:    0,
			Reverse: true,
		},
	}

	f, err := createFrame(session, gbh)
	if err != nil {
		return nil, fmt.Errorf("error creating getBlockHeaders frame: %v", err)
	}

	return f, nil
}
func CreateFrameGetBlockBodies(session *session.Session) ([]byte, error) {
	// genesis, err := HexToBytes("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	// if err != nil {
	// 	return nil, fmt.Errorf("error creating hex bytes block: %v", err)
	// }

	rndBlock, err := HexToBytes("8df98812e258a7e8ed2f566745406bc4dd240ff740922232d24e501a22093094")
	if err != nil {
		return nil, fmt.Errorf("error creating hex bytes block: %v", err)
	}
	gbb := GetBlockBodies{
		RequestID:   12,
		BlockHashes: [][shaLen]byte{[shaLen]byte(rndBlock)},
	}

	f, err := createFrame(session, gbb)
	if err != nil {
		return nil, fmt.Errorf("error creating getBlockBodies frame: %v", err)
	}

	return f, nil
}

func createFrame(session *session.Session, frameContent FrameContent) ([]byte, error) {
	msg_data, err := rlp.EncodeToBytes(frameContent)
	if err != nil {
		return nil, err
	}
	if session.IsCompressionActive() {
		// use snappy
		msg_data = snappy.Encode(nil, msg_data)
	}
	b_id := rlp.AppendUint64([]byte{}, frameContent.Type())
	frame_data := append(b_id, msg_data...)
	frame_size := PutUint24(uint32(len(frame_data)))

	type HeaderData struct {
		capability_id int
		context_id    int
	}
	hd := HeaderData{
		capability_id: 0,
		context_id:    0,
	}
	header_data, err := rlp.EncodeToBytes(hd)
	if err != nil {
		return nil, err
	}

	header := append(frame_size[:], header_data...)
	header_padding := make([]byte, 16-len(header)%16)
	header = append(header, header_padding...)

	// HEADER CIPHERTEXT
	session.Enc.XORKeyStream(header, header)

	// FRAME CIPHERTEXT
	padded_len := 0
	if padding := len(frame_data) % 16; padding > 0 {
		padded_len = 16 - padding
	}
	frame_padding := make([]byte, padded_len)
	frame_data_padded := append(frame_data, frame_padding...)
	session.Enc.XORKeyStream(frame_data_padded, frame_data_padded)

	// HEADER MAC
	header_mac_tmp := session.EgressMAC.ComputeHeader(header)
	header_mac := make([]byte, len(header_mac_tmp))
	copy(header_mac, header_mac_tmp)

	// FRAME MAC
	frame_mac := session.EgressMAC.ComputeFrame(frame_data_padded)

	// FRAME
	lPadded := len(frame_data_padded)
	buf := make([]byte, sskLen*3+lPadded)
	copy(buf[0:sskLen], header)
	copy(buf[sskLen:sskLen*2], header_mac)
	copy(buf[sskLen*2:sskLen*2+lPadded], frame_data_padded)
	copy(buf[sskLen*2+lPadded:], frame_mac)

	return buf, nil
}

// ------------------------------------
// Printing

func (a *AuthMessage) String() string {
	return fmt.Sprintf("Signature: %x, InitiatorPK: %x, Nonce: %x, AuthVSN: %d", a.Signature, a.InitiatorPK, a.Nonce, a.AuthVSN)
}

func (a *AuthAck) String() string {
	return fmt.Sprintf("RecipientEphemeralKey: %x, Nonce: %x, AuthVSN: %d", a.RecipientEphemeralKey, a.Nonce, a.AuthVSN)
}

func (fh *FrameHello) String() string {
	return fmt.Sprintf("ProtocolVersion: %d, ClientID: %s, Capabilities: %v, ListenPort: %d, NodeID: %x", fh.ProtocolVersion, fh.ClientID, fh.Capabilities, fh.ListenPort, fh.NodeID)
}

func (fd *FrameDisconnect) String() string {
	return fmt.Sprintf("Reason: %d", fd.Reason)
}

func (s *Status) String() string {
	return fmt.Sprintf("Version: %d, NetworkID: %d, TotalDifficulty: %s, BlockHash: %x, Genesis: %x, ForkID: %v", s.Version, s.NetworkID, s.TotalDifficulty, s.BlockHash, s.Genesis, s.ForkID)
}

func (gbh *GetBlockHeaders) String() string {
	return fmt.Sprintf("RequestID: %d, Origin: {Hash: %x, Number: %d}, Amount: %d, Skip: %d, Reverse: %t",
		gbh.RequestId, gbh.Origin.Hash, gbh.Origin.Number, gbh.Amount, gbh.Skip, gbh.Reverse)
}

func (gbb *GetBlockBodies) String() string {
	return fmt.Sprintf("RequestID: %d, BlockHashes: %x", gbb.RequestID, gbb.BlockHashes)
}

func (bb *BlockBodies) String() string {
	var bBodiesDetails string
	for i, bBody := range bb.BBodies {
		bBodiesDetails += fmt.Sprintf("\n  BBody %d:\n    Transactions: %d\n    Uncles: %d\n    Withdrawals: %d",
			i+1, len(bBody.Transactions), len(bBody.Uncles), len(bBody.Withdrawals))
	}
	return fmt.Sprintf("RequestID: %d, BBodies: [%s\n]", bb.RequestID, bBodiesDetails)
}
