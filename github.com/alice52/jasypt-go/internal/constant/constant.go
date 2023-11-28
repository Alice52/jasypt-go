package constant

const (
	JasyptKey = "JASYPT_ENCRYPTOR_PASSWORD"
	JasyptPwd = "64179d22-8dc9-11ee-b9d1-0242ac120002"
	Prefix    = "ENC("
	Suffix    = ")"
	Pattern   = `ENC\(([^)]+)\)` //  match[1]
)

const (
	DEFAULT = "DefaultAES"
	AES     = "PBEWithAES"
	DES     = "PBEWithDES"
)
