package jasypt_go

import (
	"github.com/alice52/jasypt-go/internal/config"
	"github.com/alice52/jasypt-go/internal/constant"
	"github.com/alice52/jasypt-go/internal/encryptor"
)

func New() encryptor.Encryptor {
	return NewEncryptor(constant.AES, config.New())
}

func NewEncryptor(algorithm string, config config.Config) encryptor.Encryptor {
	switch algorithm {
	case constant.AES:
		return encryptor.NewPBEWithAES(config)
	case constant.DES:
		return encryptor.NewPBEWithDES(config)
	default:
		return encryptor.NewDefaultAES(config)
	}
}
