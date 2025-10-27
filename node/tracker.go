package node

import (
	"eth_discover/interfaces"
	"sync"
	"time"
)

type Tracker struct {
	interfaces.TrackerInterface
	track_map map[uint64]struct{}
	lock      sync.Mutex
}

func (t *Tracker) Add(request_id uint64, timeout time.Duration) {
	if t.track_map == nil {
		t.track_map = make(map[uint64]struct{})
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	t.track_map[request_id] = struct{}{}

	go func(id uint64) {
		time.Sleep(timeout)
		t.lock.Lock()
		defer t.lock.Unlock()
		delete(t.track_map, id)
	}(request_id)
}

func (t *Tracker) GetAndRemove(request_id uint64) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	_, found := t.track_map[request_id]
	if found {
		delete(t.track_map, request_id)
		return true
	}
	return false
}
