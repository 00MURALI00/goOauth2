package util

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var (
	ErrCodeGeneration =  errors.New("Random generation failed")
)

func GenerateCode(size int) (string, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	if err != nil {
		return "", ErrCodeGeneration
	}

	return hex.EncodeToString(b), nil
}
