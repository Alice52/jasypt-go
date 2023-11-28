package config

import (
	"github.com/alice52/jasypt-go/constant"
	"github.com/alice52/jasypt-go/internal/iv"
	"github.com/alice52/jasypt-go/internal/salt"
	"os"
	"strings"
)

type Config struct {
	Prefix string
	Suffix string

	Password      string
	SaltGenerator salt.Generator
	IvGenerator   iv.Generator
}

func (c *Config) NeedDecrypt(msg string) bool {
	if len(msg) == 0 {
		return false
	}

	return strings.HasPrefix(msg, c.Prefix) && strings.HasSuffix(msg, c.Suffix)
}

type Ops func(*Config)

func GetPwd() string {
	pwd := os.Getenv(constant.JasyptKey)
	if len(pwd) == 0 {
		pwd = constant.JasyptPwd
	}

	return pwd
}

func New() Config {
	return NewConfig(
		SetPrefix(constant.Prefix),
		SetSuffix(constant.Suffix),
		SetPassword(GetPwd()),
		SetSaltGenerator(salt.RandomSaltGenerator{}),
		SetIvGenerator(iv.RandomIvGenerator{}))
}

func NewConfig(configList ...Ops) Config {
	conf := Config{}
	for _, op := range configList {
		op(&conf)
	}
	return conf
}

func SetPrefix(prefix string) Ops {
	return func(con *Config) {
		con.Prefix = prefix
	}
}

func SetSuffix(suffix string) Ops {
	return func(con *Config) {
		con.Suffix = suffix
	}
}

func SetPassword(password string) Ops {
	return func(con *Config) {
		con.Password = password
	}
}

func SetSaltGenerator(generator salt.Generator) Ops {
	return func(con *Config) {
		con.SaltGenerator = generator
	}
}

func SetIvGenerator(generator iv.Generator) Ops {
	return func(con *Config) {
		con.IvGenerator = generator
	}
}
