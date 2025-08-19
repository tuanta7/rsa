package domain

type RSAPublicJWK struct {
	KeyType        string `json:"kty"`
	Modulus        string `json:"n"`
	PublicExponent string `json:"e"`
}

type RSAPrivateJWK struct {
	RSAPublicJWK
	PrivateExponent string `json:"d"`
	Prime0          string `json:"p"`
	Prime1          string `json:"q"`
	Dp              string `json:"dp"`
	Dq              string `json:"dq"`
	QInv            string `json:"qi"`
}
