package encryptor

import (
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const aesMsg = `plain text`

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestAesEncryptorWrapper(t *testing.T) {
	encryptor := NewPBEWithAES(config.New())
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

func TestAesEncryptor(t *testing.T) {
	encryptor := NewPBEWithAES(config.New())
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

func TestAesDecryptWrapper(t *testing.T) {
	encryptor := NewPBEWithAES(config.New())
	decrypt, err := encryptor.DecryptWrapper("ENC(qMZtbG1zptyIVwwMERnR2eiBEeUufzsW6BPKQ+78kRJtr5IKhN0toIwvJY3QWipC)")
	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}

func TestAesDecrypt(t *testing.T) {
	encryptor := NewPBEWithAES(config.New())
	decrypt, err := encryptor.Decrypt("mUBGluyYbVO/E/kprZghW5d1K7koy8Ww4Vf8xAujJPrYbyZdQCamkluTyP+F+xmg")

	if err != nil {
		panic(err)
	}

	assert.Equal(t, decrypt, defaultMsg)
}
