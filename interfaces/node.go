package interfaces

import (
	"encoding/hex"
	"eth_discover/session"
	"fmt"
	"net"
	"strings"
	"time"
)

type ENode struct {
	IP  net.IP
	UDP uint16
	TCP uint16
	ID  [64]byte // secp256k1 public key
}

type NodeAddress struct {
	IP   net.IP
	Port int
}
type ENodeState int

const (
	NotBondedENode ENodeState = iota
	BondedENode
	InitiatedTransport
)

type EnodeTuple struct {
	Enode ENode
	State ENodeState
}

type Config struct {
	Ip        net.IP
	UdpPort   uint16
	TcpPort   uint16
	MaxPeers  uint16
	NetworkID uint64
}

type TrackerInterface interface {
	Add(request_id uint64, timeout time.Duration)
	GetAndRemove(request_id uint64) bool
}

type NodeInterface interface {
	Init() (*NodeInterface, error)
	GetConfig() *Config
	GetAllENodes() []EnodeTuple
	TestAndSetEnode(e *ENode, oldState, newState ENodeState) bool
	UpdateENode(e *ENode, state ENodeState)
	InsertTX(session *session.Session, tx interface{})
	InsertNodeStatus(session *session.Session, status interface{})
	InsertNodeDisconnect(session *session.Session, disconnect interface{})
	InsertNodeDiscv4(id [64]byte)
	GetTracker() TrackerInterface
}

// Create ENode
func CreateEnode(s string) ENode {
	// "enode://48d7f65e900674ae6f18eb6a43c268bc368af8162556a4206bc17bf237c1ee2d971f31a32c6311f16cc5451bf89391e3f4be42c43557b44da9bd77947258ae91@80.11.78.178:30303"
	new_s := strings.Split(s, "enode://")[1]
	split_id_rest := strings.Split(new_s, "@")
	split_ip_port := strings.Split(split_id_rest[1], ":")

	// set port
	port := uint16(0)
	_, err := fmt.Sscanf(split_ip_port[1], "%d", &port)
	if err != nil {
		panic("invalid enode format: " + s)
	}

	idBytes, err := hex.DecodeString(split_id_rest[0])
	if err != nil || len(idBytes) != 64 {
		panic("invalid enode ID format")
	}
	var id [64]byte
	copy(id[:], idBytes)

	return ENode{
		IP:  net.ParseIP(split_ip_port[0]),
		UDP: port,
		TCP: port,
		ID:  id,
	}
}

//
// ------------------------------------
// Printing
//

func (e ENode) String() string {
	return fmt.Sprintf("ENode{\n"+
		"  IP: %v\n"+
		"  UDP: %d\n"+
		"  TCP: %d\n"+
		"  ID: %x\n"+
		"}",
		e.IP,
		e.UDP,
		e.TCP,
		e.ID,
	)
}

func (c Config) String() string {
	return fmt.Sprintf("Config{\n"+
		"  IP: %v\n"+
		"  UDP Port: %d\n"+
		"  TCP Port: %d\n"+
		"}",
		c.Ip,
		c.UdpPort,
		c.TcpPort,
	)
}
