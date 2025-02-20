package rlpx

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	G "eth_discover/global"
	"eth_discover/session"
	"fmt"
	mrand "math/rand"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
)

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

type Frame struct {
	HeaderCipherText [sskLen]byte
	HeaderMac        [sskLen]byte
	FrameCipherText  []byte
	FrameMac         [sskLen]byte
}

type FrameContent interface {
	Type() uint64
	GetData() ([]byte, error) // frame-data = msg-id || msg-data
}

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

// implements FrameContent
type FrameDisconnect struct {
	Reason uint64

	Rest []rlp.RawValue `rlp:"tail"`
}

// implements FrameContent
type FramePing struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

// implements FrameContent
type FramePong struct {
	Rest []rlp.RawValue `rlp:"tail"`
}

func (f Frame) GetBytes() []byte {
	buf := f.HeaderCipherText[:]
	buf = append(buf, f.HeaderMac[:]...)
	buf = append(buf, f.FrameCipherText...)
	buf = append(buf, f.FrameMac[:]...)
	return buf
}

func (fh FrameHello) GetData() ([]byte, error) {
	buf, err := rlp.EncodeToBytes(fh)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
func (fh FrameHello) Type() uint64 { return 0 }

func (fd FrameDisconnect) GetData() ([]byte, error) {
	buf, err := rlp.EncodeToBytes(fd)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
func (fd FrameDisconnect) Type() uint64 { return 1 }

func (fpi FramePing) GetData() ([]byte, error) {
	buf, err := rlp.EncodeToBytes(fpi)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
func (fpi FramePing) Type() uint64 { return 2 }

func (fpo FramePong) GetData() ([]byte, error) {
	buf, err := rlp.EncodeToBytes(fpo)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
func (fpo FramePong) Type() uint64 { return 3 }

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
		ClientID:        "https://www.linkedin.com/in/martin-lettry/", // Don't mind me, just plugging my linkedin
		Capabilities:    []Cap{cap},                                   // eth/68 for Wire
		ListenPort:      0,
		NodeID:          [64]byte(publicKeyBytes),
	}
	f, err := createFrame(session, fh)
	if err != nil {
		return nil, err
	}

	return f.GetBytes(), nil
}

func CreateFramePing(session *session.Session) ([]byte, error) {
	fp := FramePing{}
	f, err := createFrame(session, fp)
	if err != nil {
		return nil, err
	}
	return f.GetBytes(), nil
}

func CreateFramePong(session *session.Session) ([]byte, error) {
	fp := FramePong{}
	f, err := createFrame(session, fp)
	if err != nil {
		return nil, err
	}
	return f.GetBytes(), nil
}

func createFrame(session *session.Session, frameContent FrameContent) (*Frame, error) {
	msg_data, err := frameContent.GetData()
	if err != nil {
		return nil, err
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
	frame := &Frame{
		HeaderCipherText: [sskLen]byte(header),
		HeaderMac:        [sskLen]byte(header_mac),
		FrameCipherText:  frame_data_padded,
		FrameMac:         [sskLen]byte(frame_mac),
	}

	return frame, nil
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
