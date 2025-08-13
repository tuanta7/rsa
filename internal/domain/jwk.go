package domain

type RSAPublicJWK struct {
	KeyType string `json:"kty"`
	N       string `json:"n"`
	E       string `json:"e"`
}

type RSAPrivateJWK struct {
	RSAPublicJWK
	D    string `json:"d"`
	P    string `json:"p"`
	Q    string `json:"q"`
	Dp   string `json:"dp"`
	Dq   string `json:"dq"`
	QInv string `json:"qi"`
}
