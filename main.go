package main

import (
	"context"
	"eth_discover/conf"
	G "eth_discover/global"
	"eth_discover/node"
	"flag"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		ticker := time.NewTicker(3600 * time.Second)
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

	log.Info().Msgf("Disconnecting from all nodes: %v", len(session_manager.GetAllSessions()))
	cancel() // Signal all goroutines to stop
	time.Sleep(2 * time.Second)
	transport_node.Cleanup()
	os.Exit(0)
}
