package iv

import "crypto/rand"

// Generator Initialization Vector for security,
// it can contribute to encrypt the same plaintext
// produces different ciphertext each time
type Generator interface {
	GenerateIv(lengthBytes int) ([]byte, error)

	IncludeIvInEncryption() bool
}

type RandomIvGenerator struct {
}

func (g RandomIvGenerator) GenerateIv(lengthBytes int) ([]byte, error) {
	salt := make([]byte, lengthBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (g RandomIvGenerator) IncludeIvInEncryption() bool {
	return true
}
