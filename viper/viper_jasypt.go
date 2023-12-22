package jasyptv

import (
	"github.com/alice52/jasypt-go/crypt/encryptor"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

func Unmarshal(v *viper.Viper, etor encryptor.Encryptor, rawVal any, opts ...viper.DecoderConfigOption) (err error) {
	encryptor.RecoveryPanicAsError(err)

	jc := etor.GetConfig()
	for _, k := range v.AllKeys() {
		value := v.Get(k)
		if value == nil { // never happened
			continue
		}

		switch value.(type) {
		case string:
			sv := cast.ToString(value)
			if jc.NeedDecrypt(sv) {
				decrypted, err := etor.DecryptWrapper(sv)
				if err != nil {
					return err
				}
				v.Set(k, decrypted)
			}
		default:
		}
	}

	return v.Unmarshal(rawVal, opts...)
}
