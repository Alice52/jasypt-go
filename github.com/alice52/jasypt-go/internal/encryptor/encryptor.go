package encryptor

type Encryptor interface {
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)
}
