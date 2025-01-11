package messages

import (
	"fmt"
	"sync"
)

type Registry struct {
	// byte is the packet data byte
	callBacks map[byte]func(Packet)

	lock sync.Mutex
}

func (r *Registry) AddCallBack(t byte, callback func(Packet)) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.callBacks == nil {
		r.callBacks = make(map[byte]func(Packet))
	}
	r.callBacks[t] = callback
}

func (r *Registry) ExecCallBack(pd *Packet) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if callback, exists := r.callBacks[pd.Data.Type()]; exists {
		callback(*pd)
		return
	}

	fmt.Printf("callback not found for type: %d", pd.Data.Type())
}
