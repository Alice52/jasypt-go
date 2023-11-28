package encryptor

import (
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/internal/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const defaultMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestDefaultEncryptor(t *testing.T) {
	encryptor := NewDefaultAES(config.New())

	encrypt, err := encryptor.Encrypt(defaultMsg)
	if err != nil {
		return
	}

	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		return
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestDefaultDecrypt(t *testing.T) {
	encryptor := NewDefaultAES(config.New())

	decrypt, err := encryptor.Decrypt("2TIMYRtCXwH6oN7OnZvYkOJKVD7j2mRc6r7j9aFJKEFCdX+jL48=")
	if err != nil {
		return
	}

	assert.Equal(t, decrypt, defaultMsg)
}
