package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"github.com/alice52/jasypt-go/internal/config"
	"io"
)

type DefaultAES struct {
	config.Config
}

func NewDefaultAES(conf config.Config) *DefaultAES {
	return &DefaultAES{
		Config: conf,
	}
}

func (c *DefaultAES) EncryptWrapper(message string) (string, error) {
	encrypted, err := c.Encrypt(message)
	if err != nil {
		return "", err
	}

	return c.Prefix + encrypted + c.Suffix, nil
}

func (c *DefaultAES) Encrypt(message string) (string, error) {
	block, err := buildCipher(c.Password)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	seal := gcm.Seal(nonce, nonce, []byte(message), nil)

	return base64.StdEncoding.EncodeToString(seal), nil
}

func (c *DefaultAES) DecryptWrapper(message string) (string, error) {
	if c.NeedDecrypt(message) {
		s := len(c.Prefix)
		e := len(message) - len(c.Suffix)
		return c.Decrypt(message[s:e])
	}

	return message, nil
}

func (c *DefaultAES) Decrypt(message string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}

	block, err := buildCipher(c.Password)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func buildCipher(pwd string) (cipher.Block, error) {
	if len(pwd) == 0 {
		pwd = config.GetPwd()
	}

	sum := md5.Sum([]byte(pwd)) //nolint:gosec

	return aes.NewCipher(sum[:])
}
