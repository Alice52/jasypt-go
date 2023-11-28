package encryptor

import (
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/internal/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const desMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestDesEncryptor(t *testing.T) {

	encryptor := NewPBEWithDES(config.New())

	encrypt, err := encryptor.Encrypt(desMsg)
	if err != nil {
		return
	}

	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		return
	}

	assert.Equal(t, decrypt, desMsg)
}

func TestDesDecrypt(t *testing.T) {
	encryptor := NewPBEWithDES(config.New())

	decrypt, err := encryptor.Decrypt("uDlhRqsjSMxjuoXqHOWfRXruwO8F4eGcN4ua47fgUAw=")
	if err != nil {
		return
	}

	assert.Equal(t, decrypt, defaultMsg)
}
