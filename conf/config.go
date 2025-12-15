package conf

import (
	"crypto/ecdsa"
	"encoding/json"
	G "eth_discover/global"
	"eth_discover/interfaces"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

// ------------------------------------
// LOGGER SETUP

type componentFilter struct {
	component string
	writer    io.Writer
}

func (f *componentFilter) Write(p []byte) (n int, err error) {
	var entry map[string]interface{}
	if err := json.Unmarshal(p, &entry); err != nil {
		// If we can't parse it, write it anyway
		return f.writer.Write(p)
	}

	// Check if this log has our component
	if comp, ok := entry["component"].(string); ok && comp == f.component {
		return f.writer.Write(p)
	}

	// If no component match, pretend we wrote it but don't
	return len(p), nil
}

// componentExcludeFilter filters out logs with a specific component.
type componentExcludeFilter struct {
	excludeComponent string
	writer           io.Writer
}

func (f *componentExcludeFilter) Write(p []byte) (n int, err error) {
	var entry map[string]interface{}
	if err := json.Unmarshal(p, &entry); err != nil {
		// If we can't parse it, write it anyway
		return f.writer.Write(p)
	}

	// Check if this log has the excluded component
	if comp, ok := entry["component"].(string); ok && comp == f.excludeComponent {
		// Exclude this log entry
		return len(p), nil
	}

	// Otherwise, write it
	return f.writer.Write(p)
}

// Logger configs
func SetupLogger(filterComponent, excludeComponent *string) {
	// LOGGER SETUP
	zerolog.TimeFieldFormat = ""

	// Create the console writer
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}

	// Set up the writer
	var writer io.Writer = consoleWriter

	// Apply component filter if specified
	if *filterComponent != "" {
		writer = &componentFilter{
			component: *filterComponent,
			writer:    consoleWriter,
		}
	}
	if *excludeComponent != "" {
		writer = &componentExcludeFilter{
			excludeComponent: *excludeComponent,
			writer:           consoleWriter,
		}
	}
	logger := zerolog.New(writer).With().Timestamp().Logger()
	log.Logger = logger
}

// ------------------------------------
// CONFIG SETUP

type tempConfig struct {
	UdpPort    uint16 `yaml:"udp_port"`
	TcpPort    uint16 `yaml:"tcp_port"`
	PrivateKey string `yaml:"private_key"`
	MaxPeers   uint16 `yaml:"max_peers"`
	NetworkID  uint64 `yaml:"network_id"`
}

func SetupConfig(path *string) (*interfaces.Config, *ecdsa.PrivateKey, error) {
	// get public ip
	ip, err := getPublicIP()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting public ip: %v", err)
	}

	if *path == "" {
		log.Error().Msg("no path set, using default config instead")

		config := interfaces.Config{
			Ip:        ip,
			UdpPort:   30303,
			TcpPort:   30303,
			MaxPeers:  uint16(^uint16(0)), // max uint16
			NetworkID: 1,                  // mainnet
			// NetworkID: 11155111, // sepolia

		}

		G.CreatePK()
		return &config, G.PRIVATE_KEY, nil
	}

	// read config file
	data, err := os.ReadFile(*path)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading config file: %v", err)
	}

	// parse file
	var temp tempConfig
	err = yaml.Unmarshal(data, &temp)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing config file: %v", err)
	}

	// parse private key
	privateKey, err := crypto.HexToECDSA(temp.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting private key: %v", err)
	}

	config := &interfaces.Config{
		Ip:        ip,
		UdpPort:   temp.UdpPort,
		TcpPort:   temp.TcpPort,
		MaxPeers:  temp.MaxPeers,
		NetworkID: temp.NetworkID,
	}
	return config, privateKey, nil
}

func getPublicIP() (net.IP, error) {
	var ip struct {
		Query string `json:"query"`
	}
	resp, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&ip)

	if err != nil {
		return nil, err
	}
	return net.ParseIP(ip.Query), nil
	// return net.ParseIP("127.0.0.1"), nil
}
