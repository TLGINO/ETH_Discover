package session

import (
	"crypto/cipher"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type SessionManager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}

// Credits to go_ethereum for the mac logic
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

type readBuffer struct {
	data []byte
	end  int
}

// reset removes all processed data which was read since the last call to reset.
// After reset, len(b.data) is zero.
func (b *readBuffer) Reset() {
	unprocessed := b.end - len(b.data)
	copy(b.data[:unprocessed], b.data[len(b.data):b.end])
	b.end = unprocessed
	b.data = b.data[:0]
}

// read reads at least n bytes from r, returning the bytes.
// The returned slice is valid until the next call to reset.
func (b *readBuffer) Read(r io.Reader, n int) ([]byte, error) {
	offset := len(b.data)
	have := b.end - len(b.data)

	// If n bytes are available in the buffer, there is no need to read from r at all.
	if have >= n {
		b.data = b.data[:offset+n]
		return b.data[offset : offset+n], nil
	}

	// Make buffer space available.
	need := n - have
	b.Grow(need)

	// Read.
	rn, err := io.ReadAtLeast(r, b.data[b.end:cap(b.data)], need)
	if err != nil {
		return nil, err
	}
	b.end += rn
	b.data = b.data[:offset+n]
	return b.data[offset : offset+n], nil
}

// grow ensures the buffer has at least n bytes of unused space.
func (b *readBuffer) Grow(n int) {
	if cap(b.data)-b.end >= n {
		return
	}
	need := n - (cap(b.data) - b.end)
	offset := len(b.data)
	b.data = append(b.data[:cap(b.data)], make([]byte, need)...)
	b.data = b.data[:offset]
}

type peer struct {
	IP   net.IP
	TCP  uint16
	conn net.Conn
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
	isActive       bool // Whether handshake phase is over or not
	isBondedActive byte // Whether have bonded (post status)
	EgressMAC      HashMAC
	IngressMAC     HashMAC

	peer *peer
	Enc  cipher.Stream
	Dec  cipher.Stream

	Rbuf readBuffer

	handShakeState *handShakeState
}

// ----
func (s *Session) AddConn(conn net.Conn) {
	s.peer.conn = conn
}
func (s *Session) GetConn() (net.Conn, bool) {
	if s.peer.conn != nil {
		return s.peer.conn, true
	}
	return nil, false
}
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

func (s *Session) SetActive() {
	s.isActive = true
}
func (s *Session) IsActive() bool {
	return s.isActive
}

// ----

func (s *Session) SetBonded() {
	s.isBondedActive += 1
}
func (s *Session) IsBonded() bool {
	// we need to both receive and send a status message -> hence 2
	return s.isBondedActive == 0x02
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

func CreateSessionManager() *SessionManager {
	sm := SessionManager{
		sessions: make(map[string]*Session),
	}
	return &sm
}

func (sm *SessionManager) GetSession(ip string) (*Session, bool) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	session, ok := sm.sessions[ip]
	if !ok {
		return nil, false
	}
	return session, true
}

func (sm *SessionManager) AddSession(ip net.IP, tcp_port uint16) *Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	session := &Session{
		peer: &peer{IP: ip, TCP: tcp_port, conn: nil},
		handShakeState: &handShakeState{
			isInitiator:              false,
			nonces:                   &peerNonces{},
			auth:                     &authData{},
			ephemeralPrivateKey:      nil,
			remoteEphemeralPublicKey: nil,
		},
	}
	sm.sessions[ip.String()] = session
	return session
}

func (sm *SessionManager) RemoveSession(ip string) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	delete(sm.sessions, ip)
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
