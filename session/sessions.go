package session

import (
	"eth_discover/interfaces"
	"hash"
	"sync"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type SessionManager struct {
	sessions map[string]*Session
	lock     sync.Mutex
}

type Session struct {
	Enode          *interfaces.ENode
	InitiatorNonce []byte
	RecipientNonce []byte

	AuthSent     []byte
	AuthResponse []byte

	IsInitiator           bool
	EphemeralPrivateKey_1 *ecies.PrivateKey // if I am initiator
	EphemeralPrivateKey_2 *ecies.PublicKey  // if I am NOT initiator

	EphemeralKey *ecies.PrivateKey // ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
	SharedSecret [32]byte          // shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
	AESSecret    [32]byte          // aes-secret = keccak256(ephemeral-key || shared-secret)
	MACSecret    [32]byte          // mac-secret = keccak256(ephemeral-key || aes-secret)

	IngressMac hash.Hash
	EgressMac  hash.Hash
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

func (sm *SessionManager) AddSession(enode *interfaces.ENode) *Session {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	session := &Session{
		Enode:       enode,
		IsInitiator: true,
	}
	sm.sessions[enode.IP.String()] = session
	return session
}
