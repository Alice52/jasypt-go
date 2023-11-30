package encryptor

import (
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const desMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestDesEncryptorWrapper(t *testing.T) {
	encryptor := NewPBEWithDES(config.New())

	encrypt, err := encryptor.EncryptWrapper(desMsg)
	if err != nil {
		panic(err)
	}

	decrypt, err := encryptor.DecryptWrapper(encrypt)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, desMsg)
}

func TestDesEncryptor(t *testing.T) {
	encryptor := NewPBEWithDES(config.New())

	encrypt, err := encryptor.Encrypt(desMsg)
	if err != nil {
		panic(err)
	}

	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, desMsg)
}

func TestDesDecryptWrapper(t *testing.T) {
	encryptor := NewPBEWithDES(config.New())
	decrypt, err := encryptor.DecryptWrapper("ENC(PvUmKDs8QgOWiFpM6hzck84WZRMf7bcHrp2IQdm71xk=)")

	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestDesDecrypt(t *testing.T) {
	encryptor := NewPBEWithDES(config.New())
	decrypt, err := encryptor.Decrypt("uDlhRqsjSMxjuoXqHOWfRXruwO8F4eGcN4ua47fgUAw=")

	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}
