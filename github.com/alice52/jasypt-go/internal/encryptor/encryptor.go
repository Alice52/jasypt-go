package encryptor

type Encryptor interface {
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)

	EncryptWrapper(message string) (string, error)
	DecryptWrapper(message string) (string, error)
}
