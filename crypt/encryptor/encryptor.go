package encryptor

import "github.com/alice52/jasypt-go/config"

type Encryptor interface {
	GetConfig() config.Config
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)

	EncryptWrapper(message string) (string, error)
	DecryptWrapper(message string) (string, error)
}
