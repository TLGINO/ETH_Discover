package transport

import (
	"crypto/ecdsa"
	"errors"
	"eth_discover/interfaces"
	"eth_discover/rlpx"
	"eth_discover/session"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/rs/zerolog/log"
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
		if enodeTuple.State == interfaces.AnsweredFindNode {
			filteredENodes = append(filteredENodes, &enodeTuple.Enode)
		}
	}

	defer func() {
		for _, eNode := range filteredENodes {
			tn.node.UpdateENode(eNode, interfaces.InitiatedTransport)
		}
	}()

	for _, eNode := range filteredENodes {

		session := tn.sessionManager.AddSession(eNode.IP, eNode.TCP)
		session.SetInitiator() // Set ourselves as the initiator

		recipientPK, err := rlpx.PubkeyToECDSA(eNode.ID)
		if err != nil {
			log.Err(err).Str("component", "rlpx").Msg("error converting key")
			return
		}
		authMessage, err := rlpx.CreateAuthMessage(session, recipientPK)
		if err != nil {
			log.Err(err).Str("component", "rlpx").Msg("error creating auth message")
			return
		}

		tn.SendTCP(eNode.IP, eNode.TCP, authMessage)
	}
}

func (tn *TransportNode) TestHello(session *session.Session) {
	helloFrame, err := rlpx.CreateFrameHello(session)
	if err != nil {
		log.Err(err).Str("component", "rlpx").Msg("error creating hello frame")
		return
	}
	ip, port := session.To()
	tn.SendTCP(ip, port, helloFrame)
}
