// network/socket.go
package network

import (
	"encoding/json"
	"go_fun/messages"
	"net"
	"net/http"
)

type Server struct {
	tcp *TCP
	udp *UDP
}

func (s *Server) InitServer(registry *messages.Registry) error {
	s.udp = new(UDP)
	if err := s.udp.Init(registry); err != nil {
		return err
	}
	s.tcp = new(TCP)
	if err := s.tcp.Init(registry); err != nil {
		return err
	}
	return nil
}

func (s *Server) GetUDP() UDP {
	return *s.udp
}
func (s *Server) GetTCP() TCP {
	return *s.tcp
}

func (s *Server) GetPublicIP() net.IP {
	var ip struct {
		Query string `json:"query"`
	}
	resp, _ := http.Get("http://ip-api.com/json/")
	defer resp.Body.Close()
	json.NewDecoder(resp.Body).Decode(&ip)
	return net.ParseIP(ip.Query)
}

type Connection interface {
	Init(registry *messages.Registry) error
	Send(to string, data []byte) error
	GetPort() uint16
}
