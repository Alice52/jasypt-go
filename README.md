# jasypt-go

`jasypt-go` 是一个用于 Go 配置加解密的轻量级库，提供与 Jasypt 常见用法相似的 `ENC(...)` 包装格式，并支持在 Viper 读取配置时自动解密敏感字段。

适合密码、令牌、数据库连接信息等配置项的加密存储。项目默认使用基于密码的 AES 加密，同时保留 DES 和 AES-GCM 实现供兼容或特定场景使用。

## 功能特性

- 支持 `PBEWithAES`、`PBEWithDES` 和 `DefaultAES` 三种加密实现
- 支持 `ENC(...)` 格式的自动识别、包装与解密
- 从环境变量读取加密密码
- 支持自定义密码、密文前后缀、Salt 生成器和 IV 生成器
- 提供 Viper 集成，可在反序列化配置前自动解密
- 使用随机 Salt 和 IV，使相同明文可生成不同密文

## 环境要求

- Go 1.20 或更高版本

## 安装

```bash
go get github.com/alice52/jasypt-go@v1.0.7
```

## 快速开始

生产环境中应通过 `JASYPT_ENCRYPTOR_PASSWORD` 环境变量提供密码：

```bash
export JASYPT_ENCRYPTOR_PASSWORD='replace-with-a-strong-secret'
```

然后创建默认加密器。`jasypt.New()` 默认使用 `PBEWithAES`：

```go
package main

import (
	"fmt"
	"log"

	"github.com/alice52/jasypt-go"
)

func main() {
	encryptor := jasypt.New()

	encrypted, err := encryptor.EncryptWrapper("plain text")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(encrypted) // ENC(...)

	decrypted, err := encryptor.DecryptWrapper(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(decrypted) // plain text
}
```

由于默认实现使用随机 Salt 和 IV，同一段明文每次加密得到的密文通常不同，但均可使用同一个密码解密。

## 包装格式

库默认使用 `ENC(` 作为前缀、`)` 作为后缀：

```text
ENC(base64-encoded-ciphertext)
```

加解密器提供两组方法：

| 方法 | 说明 |
| --- | --- |
| `Encrypt(message)` | 返回未经 `ENC(...)` 包装的 Base64 密文 |
| `Decrypt(message)` | 解密未经包装的 Base64 密文 |
| `EncryptWrapper(message)` | 加密并添加配置中的前后缀 |
| `DecryptWrapper(message)` | 仅当内容匹配配置的前后缀时解密，否则原样返回 |

## 选择加密算法

通过 `jasypt.NewEncryptor` 选择算法：

```go
package main

import (
	"github.com/alice52/jasypt-go"
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
)

func main() {
	aesEncryptor := jasypt.NewEncryptor(constant.AES, config.New())
	desEncryptor := jasypt.NewEncryptor(constant.DES, config.New())
	defaultAESEncryptor := jasypt.NewEncryptor(constant.DEFAULT, config.New())

	_, _, _ = aesEncryptor, desEncryptor, defaultAESEncryptor
}
```

| 常量 | 算法标识 | 实现说明 | 建议用途 |
| --- | --- | --- | --- |
| `constant.AES` | `PBEWithAES` | PBKDF2-SHA512 派生 256 位密钥，AES-CBC 加密 | 默认选择 |
| `constant.DES` | `PBEWithDES` | MD5 派生密钥，DES-CBC 加密 | 仅用于兼容已有密文 |
| `constant.DEFAULT` | `DefaultAES` | 从密码派生 AES 密钥，使用 AES-GCM | 使用项目自有格式的场景 |

加密和解密必须使用相同的算法、密码、前后缀以及 Salt/IV 处理方式。

## 自定义配置

可以通过函数式选项创建配置：

```go
package main

import (
	"os"

	"github.com/alice52/jasypt-go"
	"github.com/alice52/jasypt-go/config"
	"github.com/alice52/jasypt-go/constant"
	"github.com/alice52/jasypt-go/crypt/iv"
	"github.com/alice52/jasypt-go/crypt/salt"
)

func main() {
	cfg := config.NewConfig(
		config.SetPrefix("ENC["),
		config.SetSuffix("]"),
		config.SetPassword(os.Getenv(constant.JasyptKey)),
		config.SetSaltGenerator(salt.RandomSaltGenerator{}),
		config.SetIvGenerator(iv.RandomIvGenerator{}),
	)

	encryptor := jasypt.NewEncryptor(constant.AES, cfg)
	_, _ = encryptor.EncryptWrapper("plain text")
}
```

默认配置由 `config.New()` 创建：

| 配置项 | 默认值 |
| --- | --- |
| 前缀 | `ENC(` |
| 后缀 | `)` |
| 密码 | 环境变量 `JASYPT_ENCRYPTOR_PASSWORD`；未设置时使用内置默认值 |
| Salt 生成器 | `salt.RandomSaltGenerator{}` |
| IV 生成器 | `iv.RandomIvGenerator{}` |

也可以实现以下接口以接入自定义 Salt 或 IV 策略：

```go
type Generator interface {
	GenerateSalt(lengthBytes int) ([]byte, error)
	IncludeIvInEncryption() bool
}
```

```go
type Generator interface {
	GenerateIv(lengthBytes int) ([]byte, error)
	IncludeIvInEncryption() bool
}
```

`IncludeIvInEncryption` 这个名称同时存在于两个接口中：对于 Salt 生成器，它决定 Salt 是否写入密文；对于 IV 生成器，它决定 IV 是否写入密文。

## 集成 Viper

`viper` 子包会遍历 Viper 中的字符串配置值，解密匹配 `ENC(...)` 格式的内容，再将结果反序列化到目标结构体。

配置文件示例：

```yaml
system:
  env: local
  db-type: ENC(...)
  addr: ENC(...)
```

读取并解密：

```go
package main

import (
	"log"

	"github.com/alice52/jasypt-go"
	jasyptv "github.com/alice52/jasypt-go/viper"
	"github.com/spf13/viper"
)

type Config struct {
	System struct {
		Env    string `mapstructure:"env"`
		DBType string `mapstructure:"db-type"`
		Addr   int    `mapstructure:"addr"`
	} `mapstructure:"system"`
}

func main() {
	v := viper.New()
	v.SetConfigFile("config.yaml")
	if err := v.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	var cfg Config
	if err := jasyptv.Unmarshal(v, jasypt.New(), &cfg); err != nil {
		log.Fatal(err)
	}
}
```

非字符串值不会被解密。对于需要解密为整数或布尔值的配置，请在 YAML 等配置文件中先以 `ENC(...)` 字符串保存；解密后，Viper 会在反序列化时转换目标类型。

## 安全建议

- 务必在生产环境设置强随机的 `JASYPT_ENCRYPTOR_PASSWORD`，不要依赖源码中的内置默认密码。
- 不要把真实密码、明文敏感信息或包含密码的环境文件提交到版本控制系统。
- `PBEWithDES` 使用 DES 和 MD5，`DefaultAES` 也使用 MD5 派生密钥；二者仅建议用于兼容已有数据或已有格式。新数据优先使用默认的 `PBEWithAES`。
- 密码丢失后无法从密文中恢复，请通过密钥管理服务或安全的部署系统保存密码并制定轮换方案。
- 此库适合保护静态配置，但不能替代访问控制、密钥管理和传输层加密。

## API 概览

```go
type Encryptor interface {
	GetConfig() config.Config
	Encrypt(message string) (string, error)
	Decrypt(message string) (string, error)
	EncryptWrapper(message string) (string, error)
	DecryptWrapper(message string) (string, error)
}
```

主要入口：

- `jasypt.New()`：创建使用默认配置的 `PBEWithAES` 加密器。
- `jasypt.NewEncryptor(algorithm, config)`：创建指定算法和配置的加密器。
- `config.New()`：读取默认值和环境变量，生成默认配置。
- `config.NewConfig(options...)`：使用函数式选项生成自定义配置。
- `jasyptv.Unmarshal(...)`：解密 Viper 中的加密字符串并反序列化。

## 测试

```bash
go test ./...
```

## 参考项目

- [jasypt-spring-boot](https://github.com/ulisesbocchio/jasypt-spring-boot)
- [Mystery00/go-jasypt](https://github.com/Mystery00/go-jasypt)
- [wispeeer/jasypt-go](https://github.com/wispeeer/jasypt-go)

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
