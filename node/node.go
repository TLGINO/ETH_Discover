// node/node.go
package node

import (
	"database/sql"
	"encoding/hex"
	"eth_discover/interfaces"
	"eth_discover/node/discovery"
	"eth_discover/node/transport"
	"eth_discover/rlpx"
	"eth_discover/session"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/rs/zerolog/log"
)

type Node struct {
	interfaces.NodeInterface

	discoveryNode *discovery.DiscoveryNode
	transportNode *transport.TransportNode

	config *interfaces.Config

	tracker interfaces.TrackerInterface
	db      *sql.DB
}

// interface function
func Init(config *interfaces.Config) (*Node, error) {
	log.Info().Msg("Config: " + config.String())

	discovery_node, err := discovery.Init()
	if err != nil {
		return nil, fmt.Errorf("error creating discovery node: %v", err)
	}

	transport_node, err := transport.Init() // dependency injection
	if err != nil {
		return nil, fmt.Errorf("error creating transport node: %v", err)
	}

	db, err := initDB()
	if err != nil {
		return nil, fmt.Errorf("error creating sqlite db: %v", err)
	}
	n := &Node{
		discoveryNode: discovery_node,
		transportNode: transport_node,

		config:  config,
		tracker: &Tracker{},
		db:      db,
	}
	discovery_node.SetNode(n)
	transport_node.SetNode(n)

	// n.enr.Set("ip", config.Ip)
	// n.enr.Set("secp256k1", G.COMPRESSED_PUBLIC_KEY)
	// n.enr.Set("udp", config.UdpPort)
	// n.enr.Set("tcp", config.TcpPort)

	return n, nil
}

// interface function
func (n *Node) GetConfig() *interfaces.Config {
	return n.config
}

// interface function
func (n *Node) GetAllENodes() []interfaces.EnodeTuple {
	return n.discoveryNode.GetAllENodes()
}

// interface function
func (n *Node) TestAndSetEnode(e *interfaces.ENode, oldState, newState interfaces.ENodeState) bool {
	return n.discoveryNode.TestAndSetEnode(e, oldState, newState)
}

// interface function
func (n *Node) UpdateENode(e *interfaces.ENode, state interfaces.ENodeState) {
	n.discoveryNode.UpdateENode(e, state)
}

func (n *Node) GetDiscoveryNode() *discovery.DiscoveryNode {
	return n.discoveryNode
}

func (n *Node) GetTransportNode() *transport.TransportNode {
	return n.transportNode
}

func (n *Node) GetTracker() interfaces.TrackerInterface {
	return n.tracker
}

func initDB() (*sql.DB, error) {
	// create db
	db, err := sql.Open("sqlite3", "./tx_data.db")
	if err != nil {
		return nil, err
	}
	// create table
	sql := `
	CREATE TABLE IF NOT EXISTS TRANSACTIONS (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_ip TEXT NOT NULL,
		client_id TEXT NOT NULL,
		node_id TEXT NOT NULL,
		timestamp DATETIME DEFAULT (datetime('now', 'utc')),
		tx TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS TRANSACTIONS_RELAYED (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_ip TEXT NOT NULL,
		client_id TEXT NOT NULL,
		node_id TEXT NOT NULL,
		timestamp DATETIME DEFAULT (datetime('now', 'utc')),
		tx TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS NODE_STATUS (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_ip TEXT NOT NULL,
		client_id TEXT NOT NULL,
		node_id TEXT NOT NULL,
		s_version TEXT NOT NULL,
		s_network_id TEXT NOT NULL,
		s_td TEXT NOT NULL,
		timestamp DATETIME DEFAULT (datetime('now', 'utc'))
	);
	CREATE TABLE IF NOT EXISTS NODE_DISCONNECT (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_ip TEXT NOT NULL,
		client_id TEXT NOT NULL,
		node_id TEXT NOT NULL,
		disconnect_reason TEXT NOT NULL,
		timestamp DATETIME DEFAULT (datetime('now', 'utc'))
	);
	CREATE TABLE IF NOT EXISTS NODE_DISCV4 (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		timestamp DATETIME DEFAULT (datetime('now', 'utc'))
	);
	`

	_, err = db.Exec(sql)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (n *Node) InsertTX(session *session.Session, data interface{}, isRelay bool) {
	tx, _ := data.(*types.Transaction)

	// Parse transaction
	raw, err := tx.MarshalBinary()
	if err != nil {
		log.Err(err).Msg("failed to marshal transaction")
		return
	}
	tx_data := ("0x" + hex.EncodeToString(raw))

	// Get node data
	net_ip, _ := session.To()
	ip := net_ip.String()
	clientID, nodeIDRaw := session.GetNodeID()
	nodeID := hex.EncodeToString(nodeIDRaw[:])

	// Write to db
	var sql string
	if !isRelay {
		sql = `
		INSERT INTO TRANSACTIONS (client_ip, client_id, node_id, tx, timestamp)
		VALUES (?, ?, ?, ?, datetime('now', 'utc'))`

	} else {
		sql = `
		INSERT INTO TRANSACTIONS_RELAYED (client_ip, client_id, node_id, tx, timestamp)
		VALUES (?, ?, ?, ?, datetime('now', 'utc'))`

	}
	_, err = n.db.Exec(sql, ip, clientID, nodeID, tx_data)
	if err != nil {
		log.Err(err).Msg("failed to insert transaction into database")
		return
	}
}

func (n *Node) InsertNodeStatus(session *session.Session, data interface{}) {
	status, _ := data.(*rlpx.Status)
	// Get node data
	net_ip, _ := session.To()
	ip := net_ip.String()
	clientID, nodeIDRaw := session.GetNodeID()
	nodeID := hex.EncodeToString(nodeIDRaw[:])

	// Write to db
	sql := `
	INSERT INTO NODE_STATUS (client_ip, client_id, node_id, s_version, s_network_id, s_td, timestamp)
	VALUES (?, ?, ?, ?, ?, ?, datetime('now', 'utc'))`
	_, err := n.db.Exec(sql, ip, clientID, nodeID, status.Version, status.NetworkID, status.TotalDifficulty.String())
	if err != nil {
		log.Err(err).Msg("failed to insert transaction into database")
		return
	}
}

func (n *Node) InsertNodeDisconnect(session *session.Session, data interface{}) {
	disconnect, _ := data.(*rlpx.FrameDisconnect)

	// Get node data
	net_ip, _ := session.To()
	ip := net_ip.String()
	clientID, nodeIDRaw := session.GetNodeID()
	nodeID := hex.EncodeToString(nodeIDRaw[:])

	// Write to db
	sql := `
	INSERT INTO NODE_DISCONNECT (client_ip, client_id, node_id, disconnect_reason, timestamp)
	VALUES (?, ?, ?, ?, datetime('now', 'utc'))`
	_, err := n.db.Exec(sql, ip, clientID, nodeID, disconnect.Reason)
	if err != nil {
		log.Err(err).Msg("failed to insert disc reason into database")
		return
	}
}

func (n *Node) InsertNodeDiscv4(id [64]byte) {
	// Get node data
	nodeID := hex.EncodeToString(id[:])

	// Write to db
	sql := `
	INSERT INTO NODE_DISCV4 (node_id, timestamp)
	VALUES (?, datetime('now', 'utc'))`
	_, err := n.db.Exec(sql, nodeID)
	if err != nil {
		log.Err(err).Msg("failed to insert nodeID into database")
		return
	}
}
