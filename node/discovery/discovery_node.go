package discovery

import (
	"eth_discover/interfaces"
	"net"
	"strconv"
	"sync"
)

type DiscoveryNode struct {
	node interfaces.NodeInterface // dependency injection

	udp      *UDP
	registry *Registry

	eNodes     map[[64]byte]interfaces.EnodeTuple // map of ENode id to enode and enodestate
	eNodesLock sync.Mutex

	awaitPong     map[[32]byte]chan (struct{}) // used to wait for a pong
	awaitPongLock sync.Mutex

	awaitNeighbour     map[string]chan (struct{}) // used to wait for a neighbour
	awaitNeighbourLock sync.Mutex
}

func Init() (*DiscoveryNode, error) {
	dn := DiscoveryNode{
		udp:      new(UDP),
		registry: &Registry{},

		eNodes:         make(map[[64]byte]interfaces.EnodeTuple),
		awaitPong:      make(map[[32]byte]chan struct{}),
		awaitNeighbour: make(map[string]chan struct{}),
	}
	if err := dn.udp.Init(dn.registry); err != nil {
		return nil, err
	}

	e1 := interfaces.ENode{
		IP:  net.ParseIP("18.138.108.67"),
		UDP: 30303,
		TCP: 0,
		ID:  [64]byte{0xd8, 0x60, 0xa0, 0x1f, 0x97, 0x22, 0xd7, 0x80, 0x51, 0x61, 0x9d, 0x1e, 0x23, 0x51, 0xab, 0xa3, 0xf4, 0x3f, 0x94, 0x3f, 0x6f, 0x00, 0x71, 0x8d, 0x1b, 0x9b, 0xaa, 0x41, 0x01, 0x93, 0x2a, 0x1f, 0x50, 0x11, 0xf1, 0x6b, 0xb2, 0xb1, 0xbb, 0x35, 0xdb, 0x20, 0xd6, 0xfe, 0x28, 0xfa, 0x0b, 0xf0, 0x96, 0x36, 0xd2, 0x6a, 0x87, 0xd3, 0x1d, 0xe9, 0xec, 0x62, 0x03, 0xee, 0xed, 0xb1, 0xf6, 0x66},
	}
	e2 := interfaces.ENode{
		IP:  net.ParseIP("3.209.45.79"),
		UDP: 30303,
		TCP: 0,
		ID:  [64]byte{0x22, 0xa8, 0x23, 0x2c, 0x3a, 0xbc, 0x76, 0xa1, 0x6a, 0xe9, 0xd6, 0xc3, 0xb1, 0x64, 0xf9, 0x87, 0x75, 0xfe, 0x22, 0x6f, 0x09, 0x17, 0xb0, 0xca, 0x87, 0x11, 0x28, 0xa7, 0x4a, 0x8e, 0x96, 0x30, 0xb4, 0x58, 0x46, 0x08, 0x65, 0xba, 0xb4, 0x57, 0x22, 0x1f, 0x1d, 0x44, 0x8d, 0xd9, 0x79, 0x1d, 0x24, 0xc4, 0xe5, 0xd8, 0x87, 0x86, 0x18, 0x0a, 0xc1, 0x85, 0xdf, 0x81, 0x3a, 0x68, 0xd4, 0xde},
	}
	e3 := interfaces.ENode{
		IP:  net.ParseIP("65.108.70.101"),
		UDP: 30303,
		TCP: 0,
		ID:  [64]byte{0x2b, 0x25, 0x2a, 0xb6, 0xa1, 0xd0, 0xf9, 0x71, 0xd9, 0x72, 0x2c, 0xb8, 0x39, 0xa4, 0x2c, 0xb8, 0x1d, 0xb0, 0x19, 0xba, 0x44, 0xc0, 0x87, 0x54, 0x62, 0x8a, 0xb4, 0xa8, 0x23, 0x48, 0x70, 0x71, 0xb5, 0x69, 0x53, 0x17, 0xc8, 0xcc, 0xd0, 0x85, 0x21, 0x9c, 0x3a, 0x03, 0xaf, 0x06, 0x34, 0x95, 0xb2, 0xf1, 0xda, 0x8d, 0x18, 0x21, 0x8d, 0xa2, 0xd6, 0xa8, 0x29, 0x81, 0xb4, 0x5e, 0x6f, 0xfc},
	}
	e4 := interfaces.ENode{
		IP:  net.ParseIP("157.90.35.166"),
		UDP: 30303,
		TCP: 0,
		ID:  [64]byte{0x4a, 0xeb, 0x4a, 0xb6, 0xc1, 0x4b, 0x23, 0xe2, 0xc4, 0xcf, 0xdc, 0xe8, 0x79, 0xc0, 0x4b, 0x07, 0x48, 0xa2, 0x0d, 0x8e, 0x9b, 0x59, 0xe2, 0x5d, 0xed, 0x2a, 0x08, 0x14, 0x3e, 0x26, 0x5c, 0x6c, 0x25, 0x93, 0x6e, 0x74, 0xcb, 0xc8, 0xe6, 0x41, 0xe3, 0x31, 0x2c, 0xa2, 0x88, 0x67, 0x3d, 0x91, 0xf2, 0xf9, 0x3f, 0x8e, 0x27, 0x7d, 0xe3, 0xcf, 0xa4, 0x44, 0xec, 0xda, 0xaf, 0x98, 0x20, 0x52},
	}

	dn.AddENode(&e1)
	dn.AddENode(&e2)
	dn.AddENode(&e3)
	dn.AddENode(&e4)

	dn.registry.AddCallBack(0x01, dn.ExecPing)
	dn.registry.AddCallBack(0x02, dn.ExecPong)
	dn.registry.AddCallBack(0x03, dn.ExecFindNode)
	dn.registry.AddCallBack(0x04, dn.ExecNeighbors)
	dn.registry.AddCallBack(0x05, dn.ExecENRRequest)
	dn.registry.AddCallBack(0x06, dn.ExecENRResponse)

	return &dn, nil
}

func (dn *DiscoveryNode) SetNode(n interfaces.NodeInterface) {
	dn.node = n
}

func (dn *DiscoveryNode) SendUDP(toIP net.IP, toPort uint16, data []byte) error {
	var toAddr string
	if toIP.To4() != nil {
		toAddr = toIP.String() + ":" + strconv.Itoa(int(toPort))
	} else {
		toAddr = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
	}
	return dn.udp.Send(toAddr, data)
}

//
// ------------------------------------
// Logic for handling ENodes
//

func (dn *DiscoveryNode) AddENode(e *interfaces.ENode) {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()
	if _, exists := dn.eNodes[e.ID]; !exists {
		dn.eNodes[e.ID] = interfaces.EnodeTuple{Enode: *e, State: interfaces.NotBondedENode}
	}
}
func (dn *DiscoveryNode) UpdateENode(e *interfaces.ENode, state interfaces.ENodeState) {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()
	dn.eNodes[e.ID] = interfaces.EnodeTuple{Enode: *e, State: state}
}

func (dn *DiscoveryNode) GetAllENodes() []interfaces.EnodeTuple {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()

	enodes := make([]interfaces.EnodeTuple, 0, len(dn.eNodes))
	for _, enode := range dn.eNodes {
		enodes = append(enodes, enode)
	}
	return enodes
}

//
// ------------------------------------
// Logic for handling Pongs
//

func (dn *DiscoveryNode) AddAwaitPong(hash [32]byte, ch chan struct{}) {
	dn.awaitPongLock.Lock()
	defer dn.awaitPongLock.Unlock()
	dn.awaitPong[hash] = ch
}
func (dn *DiscoveryNode) GetAwaitPong(hash [32]byte) chan struct{} {
	dn.awaitPongLock.Lock()
	defer dn.awaitPongLock.Unlock()

	ch, found := dn.awaitPong[hash]
	if !found {
		return nil
	}
	return ch
}
func (dn *DiscoveryNode) RemoveAwaitPong(hash [32]byte) {
	dn.awaitPongLock.Lock()
	defer dn.awaitPongLock.Unlock()
	delete(dn.awaitPong, hash)

}

//
// ------------------------------------
// Logic for handling Neighbours
//

func (dn *DiscoveryNode) AddAwaitNeighbours(ip string, ch chan struct{}) {
	dn.awaitNeighbourLock.Lock()
	defer dn.awaitNeighbourLock.Unlock()
	dn.awaitNeighbour[ip] = ch
}
func (dn *DiscoveryNode) GetAwaitNeighbours(ip string) chan struct{} {
	dn.awaitNeighbourLock.Lock()
	defer dn.awaitNeighbourLock.Unlock()

	ch, found := dn.awaitNeighbour[ip]
	if !found {
		return nil
	}
	return ch
}
func (dn *DiscoveryNode) RemoveAwaitNeighbours(ip string) {
	dn.awaitNeighbourLock.Lock()
	defer dn.awaitNeighbourLock.Unlock()
	delete(dn.awaitNeighbour, ip)

}
