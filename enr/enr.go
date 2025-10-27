package enr

import (
	G "eth_discover/global"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type pair struct {
	k string
	v rlp.RawValue
}

func GetENR() []byte {
	// Encode the content: [seq, "id", "v4"]
	entry, err := rlp.EncodeToBytes("v4")
	if err != nil {
		panic("Error encoding ENR id: " + err.Error())
	}

	content := []pair{
		{k: "id", v: entry},
	}

	// Flatten content into list: [seq, k, v, ...]
	var contentList []interface{}
	contentList = append(contentList, uint64(1)) // seq
	for _, p := range content {
		contentList = append(contentList, p.k, p.v)
	}

	contentRLP, err := rlp.EncodeToBytes(contentList)
	if err != nil {
		panic("Error encoding content: " + err.Error())
	}

	// Sign content: sig = sign(keccak256(content))
	hash := crypto.Keccak256(contentRLP)
	sig, err := crypto.Sign(hash, G.PRIVATE_KEY)
	if err != nil {
		panic("Error signing ENR: " + err.Error())
	}
	// Drop recovery ID (last byte)
	sig = sig[:64]

	// Build full record: [signature, seq, k, v, ...]
	record := append([]interface{}{sig}, contentList...)
	fullRLP, err := rlp.EncodeToBytes(record)
	if err != nil {
		panic("Error encoding ENR record: " + err.Error())
	}

	return fullRLP
}
