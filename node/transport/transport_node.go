package transport

import (
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	_ "github.com/mattn/go-sqlite3"

	"eth_discover/interfaces"
	"eth_discover/session"

	"github.com/rs/zerolog/log"
)

type TransportNode struct {
	node interfaces.NodeInterface // dependency injection

	tcp      *TCP
	registry *Registry

	sessionManager *session.SessionManager

	// keep track of which peer sent us which TX hash
	txHashSender map[[32]byte]map[string]struct{}
	// save the mapping from TX hash to TX
	txHashMap        map[[32]byte]*types.Transaction
	txHashSenderLock sync.RWMutex
}

func Init() (*TransportNode, error) {

	tn := TransportNode{
		tcp:      new(TCP),
		registry: &Registry{},

		sessionManager: session.CreateSessionManager(),
	}

	tn.registry.AddCallBack(0x01, tn.ExecAuth)
	tn.registry.AddCallBack(0x02, tn.ExecAuthAck)
	tn.registry.AddCallBack(0x03, tn.ExecFrame)

	return &tn, nil
}

func (tn *TransportNode) SetNode(n interfaces.NodeInterface) {
	tn.node = n
	if err := tn.tcp.Init(n.GetConfig().TcpPort, tn.registry, tn.sessionManager, tn); err != nil {
		log.Err(err).Msg("")
	}
}

func (tn *TransportNode) GetSessionManager() *session.SessionManager {
	return tn.sessionManager
}

func (tn *TransportNode) SendTCP(session *session.Session, data []byte) {
	tn.tcp.Send(session, data)
}

func (tn *TransportNode) Cleanup() {
	// close all sessions
	sessions := tn.sessionManager.GetAllSessions()
	for _, session := range sessions {
		ip, _ := session.To()
		log.Info().Msgf("disconnecting from: %v", ip)
		tn.tcp.Close(session)
	}
}
func (tn *TransportNode) AddTxHashSender(txHash [32]byte, sender string, tx *types.Transaction) {
	tn.txHashSenderLock.Lock()
	defer tn.txHashSenderLock.Unlock()

	if tn.txHashSender == nil {
		tn.txHashSender = make(map[[32]byte]map[string]struct{})
	}
	if tn.txHashMap == nil {
		tn.txHashMap = make(map[[32]byte]*types.Transaction)
	}

	senders, ok := tn.txHashSender[txHash]
	if !ok {
		// first time we see this txHash: create sender set and store the tx (only once)
		senders = make(map[string]struct{})
		tn.txHashSender[txHash] = senders
		if tx != nil {
			tn.txHashMap[txHash] = tx
		}
	}
	senders[sender] = struct{}{}
}

// GetTransaction returns the stored Transaction for the given hash, or nil if unknown.
func (tn *TransportNode) GetTransaction(txHash [32]byte) *types.Transaction {
	tn.txHashSenderLock.RLock()
	defer tn.txHashSenderLock.RUnlock()

	if tn.txHashMap == nil {
		return nil
	}
	return tn.txHashMap[txHash]
}

func (tn *TransportNode) GetTxHashSenders(txHash [32]byte) []string {
	tn.txHashSenderLock.RLock()
	defer tn.txHashSenderLock.RUnlock()

	if tn.txHashSender == nil {
		return nil
	}

	sendersMap, ok := tn.txHashSender[txHash]
	if !ok {
		return nil
	}

	result := make([]string, 0, len(sendersMap))
	for s := range sendersMap {
		result = append(result, s)
	}
	return result
}
