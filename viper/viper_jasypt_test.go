package jasyptv

import (
	"fmt"
	"github.com/alice52/jasypt-go"
	"github.com/alice52/jasypt-go/constant"
	"github.com/spf13/viper"
	"os"
	"testing"
)

type Server struct {
	System System `mapstructure:"system" json:"system" yaml:"system"`
}

type System struct {
	Env       string `mapstructure:"env" json:"env" yaml:"env"`                      // 环境值
	JasyptPwd string `mapstructure:"jasypt-pwd" json:"jasypt-pwd" yaml:"jasypt-pwd"` // 配置加解密值
	Addr      int    `mapstructure:"addr" json:"addr" yaml:"addr"`                   // 端口值
	DbType    string `mapstructure:"db-type" json:"db-type" yaml:"db-type"`          // 数据库类型:mysql(默认)|sqlite|sqlserver|postgresql
	UseRedis  bool   `mapstructure:"use-redis" json:"use-redis" yaml:"use-redis"`    // 使用redis
	UseMongo  bool   `mapstructure:"use-mongo" json:"use-mongo" yaml:"use-mongo"`    // 使用redis
}

func TestEncrypt(t *testing.T) {
	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
	etor := jasypt.New()

	addr, _ := etor.EncryptWrapper("8888")
	dbType, _ := etor.EncryptWrapper("pgsql")
	useMongo, _ := etor.EncryptWrapper("true")
	fmt.Printf("%s, %s, %s", addr, dbType, useMongo)
}

func TestUnmarshal(t *testing.T) {

	v := viper.New()
	v.SetConfigFile("config.yaml")
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		panic(err)
	}

	os.Setenv(constant.JasyptKey, constant.JasyptPwd)
	etor := jasypt.New()
	s := new(Server)
	_ = Unmarshal(v, etor, &s)
	fmt.Printf("%#v", s)
}
