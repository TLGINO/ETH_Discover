package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

func DecodeTX(txData string) (*types.Transaction, error) {
	// Remove "0x" prefix if present
	if strings.HasPrefix(txData, "0x") {
		txData = txData[2:]
	}

	// Decode hex string to bytes
	raw, err := hex.DecodeString(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Unmarshal binary data back to transaction
	tx := new(types.Transaction)
	err = tx.UnmarshalBinary(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	return tx, nil
}

func PrintTXCompact(tx *types.Transaction) {
	from, _ := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)

	fmt.Printf("TX: %s\n", tx.Hash().Hex())
	fmt.Printf("  From: %s → To: %s\n", from.Hex(), toAddress(tx))
	fmt.Printf("  Value: %s ETH | Gas: %d @ %s Gwei | Nonce: %d\n",
		weiToEth(tx.Value()),
		tx.Gas(),
		weiToGwei(tx.GasPrice()),
		tx.Nonce())
	if len(tx.Data()) > 0 {
		fmt.Printf("  Data: %d bytes\n", len(tx.Data()))
	}
}

func weiToEth(wei *big.Int) string {
	eth := new(big.Float).SetInt(wei)
	eth = eth.Quo(eth, big.NewFloat(1e18))
	return eth.Text('f', 6)
}

func weiToGwei(wei *big.Int) string {
	gwei := new(big.Float).SetInt(wei)
	gwei = gwei.Quo(gwei, big.NewFloat(1e9))
	return gwei.Text('f', 2)
}
func toAddress(tx *types.Transaction) string {
	if tx.To() != nil {
		return tx.To().Hex()
	}
	return "[Contract Creation]"
}

func main() {
	fmt.Println(uint64(time.Now().Add(10 * time.Second).Unix()))
	return

	tx, err := DecodeTX("0xf86580843b9aca00827b0c94593eff29d27347d00d9f588a08c415cf23e6cb468080820135a0a49f92a00d5b12fb7e27896d5c6add4b1feddc6b7be600d84351ffd1384f2798a033b1964a11e6407855cfa372901d3d38738c8074aa26e8f720eef38994637f7e")
	if err != nil {
		fmt.Printf("error decoding tx: %v\n", err)
		return
	}
	PrintTXCompact(tx)
}

// ===============================
// METAMASK SENT THIS:
// ===============================
// {"id":2504952657029701,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86580843b9aca00827b0c94593eff29d27347d00d9f588a08c415cf23e6cb468080820135a0a49f92a00d5b12fb7e27896d5c6add4b1feddc6b7be600d84351ffd1384f2798a033b1964a11e6407855cfa372901d3d38738c8074aa26e8f720eef38994637f7e"]}
// ===============================

// I need to forward all requests to my main node
// but intercept the eth_sendRawTransaction for myself
