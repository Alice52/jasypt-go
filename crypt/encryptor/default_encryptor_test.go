package encryptor

import (
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const defaultMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestDefaultEncryptorWrapper(t *testing.T) {
	encryptor := NewDefaultAES(config.New())

	encrypt, err := encryptor.EncryptWrapper(defaultMsg)
	if err != nil {
		panic(err)
	}

	decrypt, err := encryptor.DecryptWrapper(encrypt)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestDefaultEncryptor(t *testing.T) {
	encryptor := NewDefaultAES(config.New())

	encrypt, err := encryptor.Encrypt(defaultMsg)
	if err != nil {
		panic(err)
	}

	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestDefaultDecryptWrapper(t *testing.T) {
	encryptor := NewDefaultAES(config.New())
	decrypt, err := encryptor.DecryptWrapper("ENC(brd70sI4VaASbukviqG/gGi9WrF9Kjtmki+WB30gnq6qBFezcb0=)")

	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestDefaultDecrypt(t *testing.T) {
	encryptor := NewDefaultAES(config.New())
	decrypt, err := encryptor.Decrypt("r0xXQ2ZijFJKEoCF43GAMx30drumSjS38lVFbUwmPzwniLfsejM=")

	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}
