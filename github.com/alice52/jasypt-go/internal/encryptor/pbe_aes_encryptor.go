package encryptor

import (
	"crypto/sha512"
	"encoding/base64"
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/util"
	"golang.org/x/crypto/pbkdf2"
	"regexp"
)

type PBEWithAES struct {
	config.Config

	algorithmBlockSize  int
	keyObtainIterations int
}

func NewPBEWithAES(conf config.Config) *PBEWithAES {
	return &PBEWithAES{
		Config:              conf,
		algorithmBlockSize:  16,
		keyObtainIterations: 1000,
	}
}

func (c *PBEWithAES) Encrypt(message string) (string, error) {

	saltGenerator, ivGenerator, password := c.SaltGenerator, c.IvGenerator, c.Password
	_, _, koi, ab := c.Prefix, c.Suffix, c.keyObtainIterations, c.algorithmBlockSize

	salt, err := saltGenerator.GenerateSalt(ab)
	if err != nil {
		return "", err
	}
	iv, err := ivGenerator.GenerateIv(ab)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), salt, koi, 32, sha512.New)
	encText, err := util.Aes256Encrypt([]byte(message), dk, iv)
	if err != nil {
		return "", err
	}
	result := encText
	if ivGenerator.IncludeIvInEncryption() {
		result = append(iv, result...)
	}
	if saltGenerator.IncludeIvInEncryption() {
		result = append(salt, result...)
	}

	return base64.StdEncoding.EncodeToString(result), nil
}

func (c *PBEWithAES) Decrypt(message string) (string, error) {
	saltGenerator, ivGenerator, password := c.SaltGenerator, c.IvGenerator, c.Password
	_, _, koi, ab := c.Prefix, c.Suffix, c.keyObtainIterations, c.algorithmBlockSize

	encrypted, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}
	var salt []byte
	var iv []byte
	if saltGenerator.IncludeIvInEncryption() {
		salt = encrypted[:ab]
		encrypted = encrypted[ab:]
	}
	if ivGenerator.IncludeIvInEncryption() {
		iv = encrypted[:ab]
		encrypted = encrypted[ab:]
	}
	dk := pbkdf2.Key([]byte(password), salt, koi, 32, sha512.New)
	text, err := util.Aes256Decrypt(encrypted, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}
