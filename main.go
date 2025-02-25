// main.go
package main

import (
	"eth_discover/conf"
	G "eth_discover/global"
	"eth_discover/node"
	"flag"
	_ "net/http/pprof"
	"time"

	"github.com/rs/zerolog/log"
)

func main() {
	// PARSE ARGS
	filterComponent := flag.String("component", "", "Filter logs by component name") // eth, discv4
	configPath := flag.String("config", "", "Set config file")
	flag.Parse()

	// LOGGER SETUP
	conf.SetupLogger(filterComponent)

	// CONFIG SETUP
	config, privateKey, err := conf.SetupConfig(configPath)
	if err != nil {
		log.Error().Err(err).Msg("error generating config")
		return
	}
	G.SetPK(privateKey)

	// NODE SETUP
	n, err := node.Init(config)
	if err != nil {
		log.Error().Err(err).Msg("")
		return
	}

	// Give the server time to start
	time.Sleep(time.Second)

	discovery_node := n.GetDiscoveryNode()
	transport_node := n.GetTransportNode()

	// discv4 | Bind to new nodes
	go func() {
		for {
			discovery_node.Bind()
		}
	}()

	// discv4 | Find new nodes
	go func() {
		for {
			discovery_node.Find()
		}
	}()

	// rlpx | Connect to new nodes
	go func() {
		for {
			transport_node.StartHandShake()
		}
	}()

	for {
		time.Sleep(5 * time.Second)
		numNeigbors := len(n.GetAllENodes())
		log.Info().Msgf("Connected to %d nodes", numNeigbors)
	}
}
