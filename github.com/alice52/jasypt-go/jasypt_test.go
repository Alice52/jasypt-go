package jasypt_go

import (
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/internal/constant"
	"github.com/alice52/jasypt-go/internal/iv"
	"github.com/alice52/jasypt-go/internal/salt"
	"os"
	"testing"
)

const (
	pwd = constant.JasyptPwd
)

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestJasypt(t *testing.T) {

	config := config.NewConfig(
		config.SetPassword(pwd),
		config.SetSaltGenerator(salt.RandomSaltGenerator{}),
		config.SetIvGenerator(iv.RandomIvGenerator{}))

	encryptor := NewEncryptor(constant.DES, config)
	encrypt, err := encryptor.Encrypt(`plain text`)
	if err != nil {
		t.Error(err)
	}
	decrypt, err := encryptor.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	if decrypt != `plain text` {
		t.Error(`decrypt failed`)
	}
}

func TestDecrypt(t *testing.T) {

	encryptor := NewEncryptor(constant.DES, config.New())

	decrypted1, err := encryptor.Decrypt("nmvk6UlTLNPJaCe8zCXM9Vo/wF/8Z8jKuQRwlG/H3yg=")
	if err != nil {
		t.Error(err)
		return
	}
	if decrypted1 != `plain text` {
		t.Error(`decrypted1 not equal to plain text`)
	}
}
