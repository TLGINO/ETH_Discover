package transport

import (
	"crypto/ecdsa"
	"errors"
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func PublicKeyFromBytes(pubKeyBytes [64]byte) (*ecdsa.PublicKey, error) {
	// First, create the full 65-byte public key by adding the 0x04 prefix
	fullPubKey := make([]byte, 65)
	fullPubKey[0] = 0x04 // Uncompressed public key prefix
	copy(fullPubKey[1:], pubKeyBytes[:])

	// Parse the public key
	curve := secp256k1.S256() // Get the secp256k1 curve
	x := new(big.Int).SetBytes(pubKeyBytes[:32])
	y := new(big.Int).SetBytes(pubKeyBytes[32:])

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("public key point is not on curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (tn *TransportNode) StartHandShake() {

	allENodeTuples := tn.node.GetAllENodes()
	var filteredENodes []*interfaces.ENode
	for _, enodeTuple := range allENodeTuples {
		// if enodeTuple.state != NotBondedENode {
		filteredENodes = append(filteredENodes, &enodeTuple.Enode)
		// }
	}
	if len(filteredENodes) == 0 {
		return
	}
	println(len(filteredENodes))
	for _, eNode := range filteredENodes {

		session := tn.sessionManager.AddSession(eNode)
		recipientPK, err := rlpx.PubkeyToECDSA(session.Enode.ID)
		if err != nil {
			println("HERE ERROR 0", err.Error())
			return
		}
		authMessage, err := rlpx.CreateAuthBody(session, recipientPK)
		if err != nil {
			println("HERE ERROR 1", err.Error())
			return
		}

		println(eNode.String())

		err = tn.SendTCP(eNode.IP, eNode.TCP, authMessage)
		if err != nil {
			fmt.Print("error sending: " + err.Error())
			continue
		}
		time.Sleep(1 * time.Second)
		continue
	}
}
