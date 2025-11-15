package key

import (
	"bytes"
	"encoding/binary"
)

type BigEndianSequence []byte

func IntToBigEndian(i int) BigEndianSequence {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(i))
	return bytes.TrimLeft(data, "\x00")
}
