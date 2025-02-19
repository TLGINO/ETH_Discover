package transport

import (
	"eth_discover/rlpx"
	"eth_discover/session"
	"sync"

	"github.com/rs/zerolog/log"
)

type Registry struct {
	// byte is the packet data byte
	callBacks map[byte]func(rlpx.Packet, *session.Session)

	lock sync.Mutex
}

func (r *Registry) AddCallBack(t byte, callback func(rlpx.Packet, *session.Session)) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.callBacks == nil {
		r.callBacks = make(map[byte]func(rlpx.Packet, *session.Session))
	}
	r.callBacks[t] = callback
}

func (r *Registry) ExecCallBack(pd rlpx.Packet, pType byte, session *session.Session) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if callback, exists := r.callBacks[pType]; exists {
		callback(pd, session)
		return
	}

	log.Error().Msgf("callback not found for type: %d", pType)
}
