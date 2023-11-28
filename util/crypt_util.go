package util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
)

func GetMd5DerivedKey(password string, salt []byte, count int) ([]byte, []byte) {
	var key [16]byte = md5.Sum([]byte(password + string(salt))) //nolint:gosec
	for i := 0; i < count-1; i++ {
		key = md5.Sum(key[:]) //nolint:gosec
	}

	return key[:8], key[8:]
}

func DesEncrypt(origData, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, err
	}

	origData = pKCS5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

func DesDecrypt(encrypted, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key) //nolint:gosec
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = pKCS5UnPadding(origData, block.BlockSize())
	return origData, nil
}

func Aes256Encrypt(origData, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = pKCS5Padding(origData, block.BlockSize())
	encrypted := make([]byte, len(origData))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

func Aes256Decrypt(encrypted, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = pKCS5UnPadding(origData, block.BlockSize())
	return origData, nil
}

func pKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pKCS5UnPadding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	if padding == 0 {
		return origData
	}

	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}
