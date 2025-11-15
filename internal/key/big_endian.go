package key

import (
	"encoding/binary"
)

type bigEndian []byte

func (b bigEndian) Uint64() uint64 {
	return binary.BigEndian.Uint64(b)
}
