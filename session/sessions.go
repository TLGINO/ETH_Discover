package session

import (
	"crypto/cipher"
	"fmt"
	"hash"
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type SessionManager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}
type HashMAC struct {
	cipher     cipher.Block
	hash       hash.Hash
	aesBuffer  [16]byte
	hashBuffer [32]byte
	seedBuffer [32]byte
}

func NewHashMAC(cipher cipher.Block, h hash.Hash) HashMAC {
	m := HashMAC{cipher: cipher, hash: h}
	if cipher.BlockSize() != len(m.aesBuffer) {
		panic(fmt.Errorf("invalid MAC cipher block size %d", cipher.BlockSize()))
	}
	if h.Size() != len(m.hashBuffer) {
		panic(fmt.Errorf("invalid MAC digest size %d", h.Size()))
	}
	return m
}

// computeHeader computes the MAC of a frame header.
// Add this to your MAC computation code
func (m *HashMAC) ComputeHeader(header []byte) []byte {
	sum1 := m.hash.Sum(m.hashBuffer[:0])
	return m.compute(sum1, header)
}

// computeFrame computes the MAC of framedata.
func (m *HashMAC) ComputeFrame(framedata []byte) []byte {
	m.hash.Write(framedata)
	seed := m.hash.Sum(m.seedBuffer[:0])
	return m.compute(seed, seed[:16])
}

// compute computes the MAC of a 16-byte 'seed'.
func (m *HashMAC) compute(sum1, seed []byte) []byte {
	if len(seed) != len(m.aesBuffer) {
		panic("invalid MAC seed")
	}

	m.cipher.Encrypt(m.aesBuffer[:], sum1)
	for i := range m.aesBuffer {
		m.aesBuffer[i] ^= seed[i]
	}
	m.hash.Write(m.aesBuffer[:])
	sum2 := m.hash.Sum(m.hashBuffer[:0])
	return sum2[:16]
}

type peer struct {
	IP  net.IP
	TCP uint16
}

type peerNonces struct {
	initNonce, recNonce []byte
}
type authData struct {
	// auth/auth-ack sent/received - used for mac
	auth, auth_ack []byte
}

type handShakeState struct {
	isInitiator              bool // Whether we started the connection or not
	nonces                   *peerNonces
	auth                     *authData
	ephemeralPrivateKey      *ecies.PrivateKey // if I am initiator
	remoteEphemeralPublicKey *ecies.PublicKey  // if I am NOT initiator
}

type Session struct {
	isActive            bool // Whether handshake phase is over or not
	isCompressionActive byte // Whether to use snappy or not (post hello)
	EgressMAC           HashMAC
	IngressMAC          HashMAC

	peer *peer
	Enc  cipher.Stream
	Dec  cipher.Stream

	// Deleted in Cleanup once handshake is over
	handShakeState *handShakeState
}

// ----

func (s *Session) To() (net.IP, uint16) {
	return s.peer.IP, s.peer.TCP
}

// ----

func (s *Session) SetInitNonce(b []byte) {
	s.handShakeState.nonces.initNonce = b
}
func (s *Session) SetRecNonce(b []byte) {
	s.handShakeState.nonces.recNonce = b
}

func (s *Session) GetNonces() ([]byte, []byte) {
	return s.handShakeState.nonces.initNonce, s.handShakeState.nonces.recNonce
}

// ----

func (s *Session) SetEphemeralPrivateKey(k *ecies.PrivateKey) {
	s.handShakeState.ephemeralPrivateKey = k
}

func (s *Session) GetEphemeralPrivateKey() *ecies.PrivateKey {
	return s.handShakeState.ephemeralPrivateKey
}

// ----

func (s *Session) SetRemoteEphemeralPublicKey(k *ecies.PublicKey) {
	s.handShakeState.remoteEphemeralPublicKey = k
}

func (s *Session) GetRemoteEphemeralPublicKey() *ecies.PublicKey {
	return s.handShakeState.remoteEphemeralPublicKey
}

// ----

func (s *Session) GetEgressMAC() HashMAC {
	return s.EgressMAC
}

func (s *Session) GetIngressMAC() HashMAC {
	return s.IngressMAC
}

// ----

func (s *Session) GetEnc() cipher.Stream {
	return s.Enc
}

func (s *Session) GetDec() cipher.Stream {
	return s.Dec
}

// ----

func (s *Session) SetActive() {
	s.isActive = true
}
func (s *Session) IsActive() bool {
	return s.isActive
}

// ----

func (s *Session) SetCompressionActive() {
	s.isCompressionActive += 1
}
func (s *Session) IsCompressionActive() bool {
	return s.isCompressionActive == 0x02
}

// ----

func (s *Session) SetInitiator() {
	s.handShakeState.isInitiator = true
}
func (s *Session) IsInitiator() bool {
	return s.handShakeState.isInitiator
}

// ----

func (s *Session) AddAuth(b []byte) {
	s.handShakeState.auth.auth = b
}
func (s *Session) AddAuthAck(b []byte) {
	s.handShakeState.auth.auth_ack = b
}
func (s *Session) GetAuthStates() ([]byte, []byte) {
	return s.handShakeState.auth.auth, s.handShakeState.auth.auth_ack
}

// ----

// Cleanup of variables / data used for handshake
func (s *Session) Cleanup() {
	// garbage collector should do the rest
	s.handShakeState = nil
}

func CreateSessionManager() *SessionManager {
	sm := SessionManager{
		sessions: make(map[string]*Session),
	}
	return &sm
}

func (sm *SessionManager) GetSession(ip string) *Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	return sm.sessions[ip]
}

func (sm *SessionManager) AddSession(ip net.IP, tcp_port uint16) *Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	session := &Session{
		peer: &peer{IP: ip, TCP: tcp_port},
		handShakeState: &handShakeState{
			nonces: &peerNonces{},
			auth:   &authData{},
		},
	}
	sm.sessions[ip.String()] = session
	return session
}

func (sm *SessionManager) GetAllSessions() []*Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}
