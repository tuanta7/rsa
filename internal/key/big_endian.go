package key

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
)

type Bytes struct {
	bigEndianSequence []byte
}

func NewBytes(s BigEndianSequence) *Bytes {
	if s == nil {
		return nil
	}
	return &Bytes{s}
}

func (b *Bytes) MarshalJSON() ([]byte, error) {
	b64 := base64.RawURLEncoding.EncodeToString(b.bigEndianSequence)
	return json.Marshal(b64)
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	b.bigEndianSequence, err = base64.RawURLEncoding.DecodeString(encoded)
	return err
}

func (b *Bytes) Uint64() uint64 {
	return binary.BigEndian.Uint64(b.bigEndianSequence)
}

func (b *Bytes) Int() int {
	return int(binary.BigEndian.Uint64(b.bigEndianSequence))
}

func (b *Bytes) BigInt() *big.Int {
	return new(big.Int).SetBytes(b.bigEndianSequence)
}
