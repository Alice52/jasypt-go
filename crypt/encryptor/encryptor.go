package encryptor

import (
	"errors"
	"fmt"
	"github.com/alice52/jasypt-go/config"
)

type Encryptor interface {
	GetConfig() config.Config
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)

	EncryptWrapper(message string) (string, error)
	DecryptWrapper(message string) (string, error)
}

func RecoveryPanicAsError() func(err error) {
	return func(err error) {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("recovered from panic: %v", r))
		}
	}
}
