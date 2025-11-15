package key

// JSONWebKey describes an JWK as defined by RFC 7517/7518.
//
// All numeric parameters are Base64URL-encoded, unsigned, big-endian byte sequences.
// Base64URL encoding MUST use the URL-safe alphabet and omit padding (`=`).
type JSONWebKey struct {
	KeyType         string    `json:"kty"`
	Algorithm       string    `json:"alg,omitempty"`
	Crv             string    `json:"crv,omitempty"` // for EC keys
	Use             string    `json:"use,omitempty"`
	KeyID           string    `json:"kid,omitempty"`
	SymmetricKey    []byte    `json:"k,omitempty"`
	Modulus         bigEndian `json:"n,omitempty"`
	PublicExponent  bigEndian `json:"e,omitempty"`
	PrivateExponent bigEndian `json:"d,omitempty"`
	Prime0          bigEndian `json:"p,omitempty"`
	Prime1          bigEndian `json:"q,omitempty"`
	Dp              bigEndian `json:"dp,omitempty"`
	Dq              bigEndian `json:"dq,omitempty"`
	Qi              bigEndian `json:"qi,omitempty"`
}
