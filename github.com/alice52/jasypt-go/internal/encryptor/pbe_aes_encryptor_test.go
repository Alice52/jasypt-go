package encryptor

import (
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/internal/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const aesMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestAesEncryptor(t *testing.T) {

	encryptor := NewPBEWithAES(config.New())

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

func TestAesDecrypt(t *testing.T) {

	encryptor := NewPBEWithAES(config.New())

	decrypt, err := encryptor.Decrypt("mUBGluyYbVO/E/kprZghW5d1K7koy8Ww4Vf8xAujJPrYbyZdQCamkluTyP+F+xmg")
	if err != nil {
		return
	}

	assert.Equal(t, decrypt, defaultMsg)
}
