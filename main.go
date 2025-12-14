package main

import (
	"context"
	"eth_discover/conf"
	G "eth_discover/global"
	"eth_discover/node"
	"flag"
	"fmt"
	"math/big"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse args
	filterComponent := flag.String("component", "", "Filter logs by component name")            // eth, discv4
	excludesFilterComponent := flag.String("xcomponent", "", "Excludes logs by component name") // eth, discv4
	configPath := flag.String("config", "", "Set config file")
	flag.Parse()

	// Logger setup
	conf.SetupLogger(filterComponent, excludesFilterComponent)

	// config setup
	config, privateKey, err := conf.SetupConfig(configPath)
	if err != nil {
		log.Error().Err(err).Msg("error generating config")
		return
	}
	G.SetPK(privateKey)
	G.SetConfig(config)

	fmt.Printf("Public key: %x\n", crypto.FromECDSAPub(G.PUBLIC_KEY)[1:])

	// Node setup
	n, err := node.Init(config)
	if err != nil {
		log.Error().Err(err).Msg("")
		return
	}

	// Give the server time to start
	time.Sleep(time.Second)

	discovery_node := n.GetDiscoveryNode()
	transport_node := n.GetTransportNode()
	session_manager := transport_node.GetSessionManager()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	G.StartBlockListener("wss://eth-mainnet.g.alchemy.com/v2/hNDILvs5J8QZTv8t9KJx_LK_AE7hgFR6")

	// Register block relay callback to relay blocks from Alchemy to peers
	G.RegisterBlockCallback(func(block *types.Block) {
		// Use block's difficulty if available, otherwise use a small non-zero value
		// Post-merge, difficulty is typically 0, but we use a small value to signal validity
		td := block.Difficulty()
		if td == nil || td.Cmp(big.NewInt(0)) == 0 {
			td = big.NewInt(1) // Minimal non-zero value for post-merge blocks
		}
		transport_node.RelayBlockToPeers(block, td)
	})

	go func() {
		// some ugly code to get pending transactions from alchemy, in order to attempt to become a better node
		transport_node.GetAndSendPendingTransactionFromAlchemy(ctx)
	}()
	// discv4 | Find new nodes
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessionLen := len(session_manager.GetAllSessions())
				log.Info().Msgf("Connected to %d nodes", sessionLen)
				if sessionLen < int(config.MaxPeers) {
					discovery_node.Bind()
					discovery_node.Find()
				}
			}
		}
	}()

	// rlpx | Connect to new nodes
	go func() {
		// time.Sleep(3600 * time.Second)

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				transport_node.StartHandShake()
			}
		}
	}()

	// rlpx | Send frame pings regularly
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				transport_node.SendPing()
			}
		}
	}()

	// gracefully disconnect from nodes
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	count_all_nodes := len(session_manager.GetAllSessions())
	log.Info().Msgf("Disconnecting from all nodes: %v", count_all_nodes)
	cancel() // Signal all goroutines to stop
	time.Sleep(2 * time.Second)
	transport_node.Cleanup()
	log.Info().Msgf("Disconnected from all nodes: %v", count_all_nodes)
	os.Exit(0)
}
