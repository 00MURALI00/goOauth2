package util

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrCodeGeneration = errors.New("Random generation failed")
)

var pepper = loadPepper()

const SALT_SIZE = 5
const ID_SIZE = 16

func loadPepper() string {
	pepper, err := os.ReadFile("../pepper.txt")
	if err != nil {
		return ""
	}

	return string(pepper)
}

func GenerateCode(size int) (string, error) {
	b := make([]byte, size)

	_, err := rand.Read(b)
	if err != nil {
		return "", ErrCodeGeneration
	}

	return hex.EncodeToString(b), nil
}

func GenerateId() string {
	b := make([]byte, ID_SIZE)

	_, err := rand.Read(b)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}

func SaltAndHashPassword(password string) (string, string) {
	salt := generateSalt()
	spp := fmt.Sprintf("%s%s%s", salt, password, pepper)
	byteSsp, err := bcrypt.GenerateFromPassword([]byte(spp), bcrypt.MinCost)
	if err != nil {
		return "", ""
	}

	return string(byteSsp), salt
}

func generateSalt() string {
	b := make([]byte, SALT_SIZE)

	_, err := rand.Read(b)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(b)
}
