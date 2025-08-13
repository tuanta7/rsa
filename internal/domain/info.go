package domain

type RSAPublicKeyInfo struct {
	Modulus        int64 `json:"modulus"`
	PublicExponent int64 `json:"publicExponent"`
}

type RSAPrivateKeyInfo struct {
	Modulus         int64 `json:"modulus"`
	PrivateExponent int64 `json:"privateExponent"`
	Prime1          int64 `json:"prime1,omitempty"`
	Prime2          int64 `json:"prime2,omitempty"`
}
