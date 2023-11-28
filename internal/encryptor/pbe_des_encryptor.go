package encryptor

import (
	"encoding/base64"
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/util"
	"regexp"
)

type PBEWithDES struct {
	config.Config

	algorithmBlockSize  int
	keyObtainIterations int
}

func NewPBEWithDES(conf config.Config) *PBEWithDES {
	return &PBEWithDES{
		Config:              conf,
		algorithmBlockSize:  8,
		keyObtainIterations: 1000,
	}
}

func (c *PBEWithDES) EncryptWrapper(message string) (string, error) {
	encrypted, err := c.Encrypt(message)
	if err != nil {
		return "", err
	}

	return c.Prefix + encrypted + c.Suffix, nil
}

func (c *PBEWithDES) Encrypt(message string) (string, error) {
	saltGenerator, ivGenerator, password := c.SaltGenerator, c.IvGenerator, c.Password
	_, _, koi, ab := c.Prefix, c.Suffix, c.keyObtainIterations, c.algorithmBlockSize

	// generate salt and iv
	salt, err := saltGenerator.GenerateSalt(ab)
	if err != nil {
		return "", err
	}

	dk, iv := util.GetMd5DerivedKey(password, salt, koi)
	encText, err := util.DesEncrypt([]byte(message), dk, iv)
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

func (c *PBEWithDES) DecryptWrapper(message string) (string, error) {
	if c.NeedDecrypt(message) {
		s := len(c.Prefix)
		e := len(message) - len(c.Suffix)
		return c.Decrypt(message[s:e])
	}

	return message, nil
}

func (c *PBEWithDES) Decrypt(message string) (string, error) {
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
	dk, iv := util.GetMd5DerivedKey(password, salt, koi)
	text, err := util.DesDecrypt(encrypted, dk, iv)
	if err != nil {
		return "", err
	}
	p := regexp.MustCompile(`[\x01-\x08]`)
	return p.ReplaceAllString(string(text), ""), nil
}
