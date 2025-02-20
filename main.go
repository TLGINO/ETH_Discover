// main.go
package main

import (
	G "eth_discover/global"
	"eth_discover/interfaces"
	"eth_discover/node"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

type tempConfig struct {
	Ip         string `yaml:"ip"`
	UdpPort    uint16 `yaml:"udp_port"`
	TcpPort    uint16 `yaml:"tcp_port"`
	PrivateKey string `yaml:"private_key"`
}

func configParser(path *string) (*tempConfig, error) {
	// read my config file
	data, err := ioutil.ReadFile(*path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}
	var temp tempConfig
	err = yaml.Unmarshal(data, &temp)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}
	return &temp, nil
}

func main() {
	// LOGGER SETUP
	zerolog.TimeFieldFormat = ""

	// CONFIG SETUP
	configPath := flag.String("config", "config.yaml", "path to my node's config file")
	// testConfigPath := flag.String("test-config", "test_config.yaml", "path to test node's config file")
	flag.Parse()

	// read my config file

	conf, err := configParser(configPath)
	if err != nil {
		log.Error().Err(err).Msg("error parsing config file")
		return
	}

	// parse my config values
	config := &interfaces.Config{
		Ip:      net.ParseIP(conf.Ip),
		UdpPort: conf.UdpPort,
		TcpPort: conf.TcpPort,
	}

	privateKey, err := crypto.HexToECDSA(conf.PrivateKey)
	if err != nil {
		log.Error().Err(err).Msg("invalid private key")
		return
	}
	G.SetPK(privateKey)

	// // parse test node config
	// test_conf, err := configParser(testConfigPath)
	// if err != nil {
	// 	log.Error().Err(err).Msg("error parsing test config file")
	// 	return
	// }

	// testPrivateKey, err := crypto.HexToECDSA(test_conf.PrivateKey)
	// if err != nil {
	// 	log.Error().Err(err).Msg("invalid other private key")
	// 	return
	// }

	// eNode := &interfaces.ENode{
	// 	IP:  net.ParseIP(test_conf.Ip),
	// 	UDP: test_conf.UdpPort,
	// 	TCP: test_conf.TcpPort,
	// 	ID:  [64]byte(crypto.FromECDSAPub(&testPrivateKey.PublicKey)[1:]),
	// }

	// NODE SETUP
	n, err := node.Init(config, nil)
	// n, err := node.Init(config, eNode)
	if err != nil {
		log.Error().Err(err).Msg("")
		return
	}

	// Give the server time to start
	time.Sleep(time.Second)

	discovery_node := n.GetDiscoveryNode()
	transport_node := n.GetTransportNode()
	if config.TcpPort == 30303 {
		select {}
	}

	for {

		// Bind to new nodes
		discovery_node.Bind()
		// Find new nodes
		discovery_node.Find()

		// can probably stop discovery once 10 nodes reached for now
		numNeigbors := len(n.GetAllENodes())

		log.Info().Msgf("Connected to %d nodes", numNeigbors)

		if numNeigbors >= 20 {
			log.Info().Msgf("Stopping discovery process, connected to %d nodes", numNeigbors)
			break
		}
	}

	// Start authenticating with nodes
	time.Sleep(3 * time.Second)
	transport_node.StartHandShake()

	select {}
}
