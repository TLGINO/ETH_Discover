package main

import (
	"fmt"
)

type frameBuffer struct {
	data []byte
}

func (b frameBuffer) read(start, end int) ([]byte, error) {
	if start < 0 || end < start {
		return []byte{}, fmt.Errorf("error reading from frame buffer, bad params")
	}
	if end > (len(b.data)) {
		return []byte{}, fmt.Errorf("error reading from frame buffer, length out of bounds")
	}
	return b.data[start:end], nil
}
func (b frameBuffer) add(newData []byte) {
	b.data = append(b.data, newData...)
}
func (b frameBuffer) reset() {
	b.data = b.data[:0]
}

func main() {
	b := frameBuffer{}

}
