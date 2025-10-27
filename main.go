// main.go
package main

import (
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

	// discv4 | Find new nodes
	go func() {
		// while / whenever we have too few nodes, find more
		for {
			sessionLen := len(session_manager.GetAllSessions())
			log.Info().Msgf("Connected to %d nodes", sessionLen)
			if sessionLen < int(config.MaxPeers) {
				discovery_node.Bind()
				discovery_node.Find()
			}
			time.Sleep(2 * time.Second)
		}
	}()

	// rlpx | Connect to new nodes
	go func() {
		for {
			transport_node.StartHandShake()
			time.Sleep(2 * time.Second)

		}
	}()

	// gracefully disconnect from nodes
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Info().Msgf("Disconnecting from all nodes: %v", len(transport_node.GetSessionManager().GetAllSessions()))
		transport_node.Cleanup()
		os.Exit(-1)
	}()

	// rlpx | Request blocks
	// go func() {
	// 	for {
	// 		transport_node.TestBlock()
	// 	}
	// }()

	select {}
}
