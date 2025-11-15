package config

const (
	KeyTypeRSA       = "RSA"
	KeyTypeEC        = "EC"  // Elliptic Curve
	KeyTypeOKP       = "OKP" // Octet Value Pair
	KeyTypeSymmetric = "oct" // Octet Sequence

	KeyTypeRSAPublicKey  = "RSA PUBLIC KEY"
	KeyTypeRSAPrivateKey = "RSA PRIVATE KEY"

	KeyFormatPEM = "PEM"
	KeyFormatDER = "DER"
	KeyFormatJWK = "JWK"
)
