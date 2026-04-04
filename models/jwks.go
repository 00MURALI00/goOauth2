package models

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

var (
	ErrDecodePublicKey  = errors.New("failed to decode PEM")
	ErrInvalidPublicKey = errors.New("not RSA public key")
)

func (j *JWKS) GetPublicKeyData() error {
	rawPublicKey, err := os.ReadFile("public.pem")
	if err != nil {
		return err
	}

	publicKeyDecoded, _ := pem.Decode(rawPublicKey)
	if publicKeyDecoded == nil {
		return ErrDecodePublicKey
	}

	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyDecoded.Bytes)
	if err != nil {
		return err
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidPublicKey
	}

	nBytes := pubKey.N.Bytes()
	eBytes := big.NewInt(int64(pubKey.E)).Bytes()

	nEncoded := base64.RawURLEncoding.EncodeToString(nBytes)
	eEncoded := base64.RawURLEncoding.EncodeToString(eBytes)

	j.Keys = []JWK{
		{
			Kty: "RSA",
			Kid: "key-1",
			Use: "sig",
			Alg: "RS256",
			N:   nEncoded,
			E:   eEncoded,
		},
	}
	return nil
}
