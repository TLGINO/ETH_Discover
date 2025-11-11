package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type RPCRequest struct {
	ID      interface{} `json:"id"`
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type RPCResponse struct {
	ID      interface{} `json:"id"`
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	// CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if r.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}

	// READ THE REQUEST
	body, _ := io.ReadAll(r.Body)

	fmt.Println("\n" + "===============================")
	fmt.Println("METAMASK SENT THIS:")
	fmt.Println("===============================")
	fmt.Println(string(body))
	fmt.Println("===============================" + "\n")

	// Parse it
	var req RPCRequest
	json.Unmarshal(body, &req)

	// Response
	var result interface{}

	switch req.Method {
	case "eth_chainId":
		result = "0x89" // 137 in hex (Polygon)
	case "net_version":
		result = "137"
	case "eth_accounts":
		result = []string{}
	case "eth_getBalance":
		result = "0xde0b6b3a7640000" // 1 ETH
	case "eth_gasPrice":
		result = "0x3b9aca00" // 1 Gwei
	case "eth_estimateGas":
		result = "0x5208" // 21000
	case "eth_getTransactionCount":
		result = "0x0"
	case "eth_blockNumber":
		result = "0x1"
	default:
		result = "0x0"
	}

	resp := RPCResponse{
		ID:      req.ID,
		JSONRPC: "2.0",
		Result:  result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server running on http://localhost:9545")
	fmt.Println("Add this to MetaMask:")
	fmt.Println("  RPC: http://localhost:9545")
	fmt.Println("  Chain ID: 137")
	fmt.Println("  Currency: MATIC")
	log.Fatal(http.ListenAndServe(":9545", nil))
}
