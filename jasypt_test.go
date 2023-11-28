package jasypt

import (
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
	"github.com/alice52/jasypt-go/internal/iv"
	"github.com/alice52/jasypt-go/internal/salt"
	"os"
	"testing"
)

const (
	pwd = constant.JasyptPwd
	msg = `plain text`
)

func init() {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
}

func TestJasyptWrapper(_ *testing.T) {
	config := config.NewConfig(
		config.SetPrefix(constant.Prefix),
		config.SetSuffix(constant.Suffix),
		config.SetPassword(pwd),
		config.SetSaltGenerator(salt.RandomSaltGenerator{}),
		config.SetIvGenerator(iv.RandomIvGenerator{}))

	encryptor := NewEncryptor(constant.DES, config)
	encrypt, err := encryptor.EncryptWrapper(msg)

	if err != nil {
		panic(err)
	}
	decrypt, err := encryptor.DecryptWrapper(encrypt)

	if err != nil && decrypt != msg {
		panic(err)
	}

}

func TestJasypt(_ *testing.T) {
	config := config.NewConfig(
		config.SetPassword(pwd),
		config.SetSaltGenerator(salt.RandomSaltGenerator{}),
		config.SetIvGenerator(iv.RandomIvGenerator{}))

	encryptor := NewEncryptor(constant.DES, config)
	encrypt, err := encryptor.Encrypt(msg)

	if err != nil {
		panic(err)
	}
	decrypt, err := encryptor.Decrypt(encrypt)

	if err != nil && decrypt != msg {
		panic(err)
	}
}

func TestDecryptWrapper(_ *testing.T) {
	encryptor := NewEncryptor(constant.DES, config.New())

	decrypted1, err := encryptor.DecryptWrapper("ENC(RS5GHdBJujp+d1Gs3wxGGAzYvbtX6AGOVqJu5fJEFHM=)")
	if err != nil && decrypted1 != msg {
		panic(err)
	}

	encryptor.DecryptWrapper("pwd")
	if err != nil && decrypted1 != "pwd" {
		panic(err)
	}

}

func TestDecrypt(_ *testing.T) {
	encryptor := NewEncryptor(constant.DES, config.New())
	decrypted1, err := encryptor.Decrypt("nmvk6UlTLNPJaCe8zCXM9Vo/wF/8Z8jKuQRwlG/H3yg=")
	if err != nil && decrypted1 != msg {
		panic(err)
	}
}
