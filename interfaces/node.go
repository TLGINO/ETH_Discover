package interfaces

import (
	"fmt"
	"net"
)

type ENode struct {
	IP  net.IP
	UDP uint16
	TCP uint16
	ID  [64]byte // secp256k1 public key
}
type ENodeState int

const (
	NotBondedENode ENodeState = iota
	BondedENode
	AnsweredFindNode
)

type EnodeTuple struct {
	Enode ENode
	State ENodeState
}

type Config struct {
	Ip      net.IP
	UdpPort uint16
	TcpPort uint16
}
type NodeInterface interface {
	Init() (*NodeInterface, error)
	GetConfig() *Config
	GetAllENodes() []EnodeTuple
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
