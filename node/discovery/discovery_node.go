package discovery

import (
	"eth_discover/interfaces"
	"net"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
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

	return &dn, nil
}

func (dn *DiscoveryNode) SetNode(n interfaces.NodeInterface) {
	dn.node = n
	if err := dn.udp.Init(n.GetConfig().UdpPort, dn.registry, dn); err != nil {
		log.Err(err).Msg("")
	}

	// taken from https://github.com/ethereum/go-ethereum/blob/master/params/bootnodes.go
	// mainnet
	e1 := interfaces.CreateEnode("enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:30303") // bootnode-aws-ap-southeast-1-001
	e2 := interfaces.CreateEnode("enode://22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de@3.209.45.79:30303")   // bootnode-aws-us-east-1-001
	e3 := interfaces.CreateEnode("enode://2b252ab6a1d0f971d9722cb839a42cb81db019ba44c08754628ab4a823487071b5695317c8ccd085219c3a03af063495b2f1da8d18218da2d6a82981b45e6ffc@65.108.70.101:30303") // bootnode-hetzner-hel
	e4 := interfaces.CreateEnode("enode://4aeb4ab6c14b23e2c4cfdce879c04b0748a20d8e9b59e25ded2a08143e265c6c25936e74cbc8e641e3312ca288673d91f2f93f8e277de3cfa444ecdaaf982052@157.90.35.166:30303") // bootnode-hetzner-fsn

	// sepolia
	// s1 := interfaces.CreateEnode("enode://4e5e92199ee224a01932a377160aa432f31d0b351f84ab413a8e0a42f4f36476f8fb1cbe914af0d9aef0d51665c214cf653c651c4bbd9d5550a934f241f1682b@138.197.51.181:30303") // sepolia-bootnode-1-nyc3
	// s2 := interfaces.CreateEnode("enode://143e11fb766781d22d92a2e33f8f104cddae4411a122295ed1fdb6638de96a6ce65f5b7c964ba3763bba27961738fef7d3ecc739268f3e5e771fb4c87b6234ba@146.190.1.103:30303")  // sepolia-bootnode-1-sfo3
	// s3 := interfaces.CreateEnode("enode://8b61dc2d06c3f96fddcbebb0efb29d60d3598650275dc469c22229d3e5620369b0d3dedafd929835fe7f489618f19f456fe7c0df572bf2d914a9f4e006f783a9@170.64.250.88:30303")  // sepolia-bootnode-1-syd1
	// s4 := interfaces.CreateEnode("enode://10d62eff032205fcef19497f35ca8477bea0eadfff6d769a147e895d8b2b8f8ae6341630c645c30f5df6e67547c03494ced3d9c5764e8622a26587b083b028e8@139.59.49.206:30303")  // sepolia-bootnode-1-blr1
	// s5 := interfaces.CreateEnode("enode://9e9492e2e8836114cc75f5b929784f4f46c324ad01daf87d956f98b3b6c5fcba95524d6e5cf9861dc96a2c8a171ea7105bb554a197455058de185fa870970c7c@138.68.123.152:30303") // sepolia-bootnode-1-ams3

	// polygon
	// p1 := interfaces.CreateEnode("enode://07bc4cf87ff8f4e7dc51280991809940f26e846c944609ae4726309be73742a830040cd783989f6941e1b41c02405834bc6365059403a59ca9255ac695156235@34.89.75.187:30303")
	// p2 := interfaces.CreateEnode("enode://f81234949f791624d1196eb3a780490f5a8199b476c3522335e6d76ca96aa9155ad21c308864b1e22ab9a53136b486520b33515310f8f18485ab471826ae9ded@34.142.43.249:30303")
	// p3 := interfaces.CreateEnode("enode://a0bc4dd2b59370d5a375a7ef9ac06cf531571005ae8b2ead2e9aaeb8205168919b169451fb0ef7061e0d80592e6ed0720f559bd1be1c4efb6e6c4381f1bdb986@35.246.99.203:30303")
	// p4 := interfaces.CreateEnode("enode://f2b0d50e0b843d38ddcab59614f93065e2c82130100032f86ae193eb874505de12fcaf12502dfd88e339b817c0b374fa4b4f7c4d5a4d1aa04f29c503d95e0228@35.197.233.240:30303")
	// p5 := interfaces.CreateEnode("enode://8a3f21c293c913a1148116a295aa69fdf41b9c5b0b0628d49be751aa8c025ae2ec1973d6d84cea8e2aba5541b5d76219dfaae41a124d42d0f56d4e1af50b74f8@35.246.95.65:30303")
	// p6 := interfaces.CreateEnode("enode://f5cfe35f47ed928d5403aa28ee616fd64ed7daa527b5ae6a7bc412ca25eaad9b6bf2f776144fd9f8e7e9c80b5360a9c03b67f1d47ea88767def7d391cc7e0cd1@34.105.180.11:30303")
	// p7 := interfaces.CreateEnode("enode://fc7624241515f9d5e599a396362c29de92b13a048ad361c90dd72286aa4cca835ba65e140a46ace70cc4dcb18472a476963750b3b69d958c5f546d48675880a8@34.147.169.102:30303")
	// p8 := interfaces.CreateEnode("enode://a36848f536ff6c431e9e3ccbb2f859a5c71f6e5e2d282d8dc6e0199618256444c5032f4cbf7e8579da9fa4d30251b7a55a2d6d3711516112e8dced057c8596c6@34.89.55.74:30303")

	// localNode := interfaces.CreateEnode("enode://c7ab3a207a1b8041ee6c35efeb0c9f7985ed9286ba906be3ff75eb163572185a85343c0ec1e33565190be57ddfc5e5eef674532e7483707302c9fd77602e55d9@127.0.0.1:33333")

	// mainnnet
	dn.AddENode(&e1)
	dn.UpdateENode(&e1, interfaces.NotBondedENode)
	dn.AddENode(&e2)
	dn.UpdateENode(&e2, interfaces.NotBondedENode)
	dn.AddENode(&e3)
	dn.UpdateENode(&e3, interfaces.NotBondedENode)
	dn.AddENode(&e4)
	dn.UpdateENode(&e4, interfaces.NotBondedENode)

	// sepolia
	// dn.AddENode(&s1)
	// dn.UpdateENode(&s1, interfaces.NotBondedENode)
	// dn.AddENode(&s2)
	// dn.UpdateENode(&s2, interfaces.NotBondedENode)
	// dn.AddENode(&s3)
	// dn.UpdateENode(&s3, interfaces.NotBondedENode)
	// dn.AddENode(&s4)
	// dn.UpdateENode(&s4, interfaces.NotBondedENode)
	// dn.AddENode(&s5)
	// dn.UpdateENode(&s5, interfaces.NotBondedENode)

	// polygon
	// dn.AddENode(&p1)
	// dn.UpdateENode(&p1, interfaces.NotBondedENode)
	// dn.AddENode(&p2)
	// dn.UpdateENode(&p2, interfaces.NotBondedENode)
	// dn.AddENode(&p3)
	// dn.UpdateENode(&p3, interfaces.NotBondedENode)
	// dn.AddENode(&p4)
	// dn.UpdateENode(&p4, interfaces.NotBondedENode)
	// dn.AddENode(&p5)
	// dn.UpdateENode(&p5, interfaces.NotBondedENode)
	// dn.AddENode(&p6)
	// dn.UpdateENode(&p6, interfaces.NotBondedENode)
	// dn.AddENode(&p7)
	// dn.UpdateENode(&p7, interfaces.NotBondedENode)
	// dn.AddENode(&p8)
	// dn.UpdateENode(&p8, interfaces.NotBondedENode)

	// dn.AddENode(&localNode)
	// dn.UpdateENode(&localNode, interfaces.NotBondedENode)

	dn.registry.AddCallBack(0x01, dn.ExecPing)
	dn.registry.AddCallBack(0x02, dn.ExecPong)
	dn.registry.AddCallBack(0x03, dn.ExecFindNode)
	dn.registry.AddCallBack(0x04, dn.ExecNeighbors)
	dn.registry.AddCallBack(0x05, dn.ExecENRRequest)
	dn.registry.AddCallBack(0x06, dn.ExecENRResponse)

}

func (dn *DiscoveryNode) SendUDP(toIP net.IP, toPort uint16, data []byte) {
	var toAddr string
	if toIP.To4() != nil {
		toAddr = toIP.String() + ":" + strconv.Itoa(int(toPort))
	} else {
		toAddr = "[" + toIP.String() + "]:" + strconv.Itoa(int(toPort))
	}
	dn.udp.Send(toAddr, data)
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
		// DB logging
		dn.node.InsertNodeDiscv4(e.ID)
	}
}
func (dn *DiscoveryNode) UpdateENode(e *interfaces.ENode, state interfaces.ENodeState) {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()
	dn.eNodes[e.ID] = interfaces.EnodeTuple{Enode: *e, State: state}
}

// TestAndSetEnode sets the state only if the current state matches oldState.
// Returns true if the state was updated, false otherwise.
func (dn *DiscoveryNode) TestAndSetEnode(e *interfaces.ENode, oldState, newState interfaces.ENodeState) bool {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()
	tuple, exists := dn.eNodes[e.ID]
	if !exists || tuple.State != oldState {
		return false
	}
	dn.eNodes[e.ID] = interfaces.EnodeTuple{Enode: *e, State: newState}
	return true
}
func (dn *DiscoveryNode) GetEnodeState(e *interfaces.ENode) interfaces.ENodeState {
	dn.eNodesLock.Lock()
	defer dn.eNodesLock.Unlock()

	if tuple, exists := dn.eNodes[e.ID]; exists {
		return tuple.State
	}
	return interfaces.NotBondedENode
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
