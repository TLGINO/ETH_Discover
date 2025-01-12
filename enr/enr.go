package enr

import (
	G "go_fun/global"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type ENR struct {
	Signature []byte
	Seq       uint64
	Pairs     []Pair
}

// Pair represents a key/value pair in the ENR
type Pair struct {
	Key   string
	Value interface{}
}

// func NewENR(seq uint64) *ENR {
// 	return &ENR{
// 		Seq:   seq,
// 		Pairs: make([]Pair, 0),
// 	}
// }

func (r *ENR) Set(key string, value interface{}) {
	// Remove existing pair if present
	for i := range r.Pairs {
		if r.Pairs[i].Key == key {
			r.Pairs = append(r.Pairs[:i], r.Pairs[i+1:]...)
			break
		}
	}

	r.Pairs = append(r.Pairs, Pair{Key: key, Value: value})
	sort.Slice(r.Pairs, func(i, j int) bool {
		return r.Pairs[i].Key < r.Pairs[j].Key
	})
}

func (r *ENR) SignV4() error {
	r.Set("id", "v4")

	content, err := rlp.EncodeToBytes([]interface{}{r.Seq, r.Pairs})
	if err != nil {
		return err
	}

	contentHash := crypto.Keccak256(content)
	sig, err := crypto.Sign(contentHash, G.PRIVATE_KEY)
	if err != nil {
		return err
	}

	r.Signature = sig[:64]
	return nil
}
