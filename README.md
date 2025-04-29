# golang-fpe

[EN](./README_EN.md)

* 参考 [mysto/python-fpe](https://github.com/mysto/python-fpe) 实现
* 算法的中文解释：[保形加密](https://knowuv.com/blog/fpe_encryption?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=1)
* 数学基础：[有限域](https://knowuv.com/blog/galois_field?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=1)
* 应用：[短链系统](https://knowuv.com/blog/short-link?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=1)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# FF3 - Golang 中的格式保留加密

这是NIST批准的FF3和FF3-1格式保留加密（FPE）算法的实现。

此包实现了NIST在2016年3月发布的800-38G _格式保留加密方法_ 中描述的FF3算法，并在2019年2月28日修订为FF3-1的草案更新。

* [NIST 推荐 SP 800-38G (FF3)](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST 推荐 SP 800-38G 修订版 1 (FF3-1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)

此包实现了对最小域大小的更改和修订的tweak长度，支持64位和56位tweak。NIST仅发布了64位tweak的官方测试向量，但使用了草案ACVP测试向量来测试FF3-1。预计最终的NIST标准将提供56位tweak长度的更新测试向量。

## 安装

`go get github.com/dusty-cjh/golang-fpe`

## 代码示例

以下示例代码使用 **base62** 编码，即 **[0-9A-Za-z]**，可以帮助您快速入门。

```golang
package main

import (
	"fmt"
	"github.com/dusty-cjh/golang-fpe/ff3"
	"log"
)

func main() {
	key := "2DE79D232DF5585D68CE47882AE256D6"
	tweak := "CBD09280979564"
	cipher, err := ff3.NewFF3Cipher(key, tweak, 62)
	if err != nil {
		log.Fatalf("创建FF3密码失败: %v", err)
	}

	plaintext := "Hello2025"
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("加密明文失败: %v", err)
	}
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("解密密文失败: %v", err)
	}

	fmt.Printf("%s -> %s -> %s\n", plaintext, ciphertext, decrypted)
}
```

## 使用

FF3是一种Feistel密码，Feistel密码通过一个表示字母表的基数（radix）进行初始化。字母表中的字符数量称为_radix_。
以下是常见的基数值：

* 基数10：数字0..9
* 基数36：字母数字0..9, a-z
* 基数62：字母数字0..9, a-z, A-Z

通过指定自定义字母表，可以支持特殊字符和国际字符集（如UTF-8）。此外，明文字符串中的所有元素共享相同的基数。因此，像A123456这样的标识号（由一个初始字母和6个数字组成）无法通过FPE正确加密并保留这种约定。

输入明文的最大长度受所选基数的限制（2 * floor(96/log2(radix)）：

* 基数10：56
* 基数36：36
* 基数62：32

为了解决字符串长度问题，可以将较长的文本分块编码。

密钥长度必须为128、192或256位。tweak为7字节（FF3-1）或8字节（原始FF3）。

与任何加密包一样，管理和保护密钥至关重要。tweak通常不需要保密。此包在初始化密码后不会将密钥存储在内存中。

## 自定义字母表

支持最多256个字符的自定义字母表。要使用由大写字母A-F组成的字母表（基数=6），可以从上述代码示例继续：

使用以下环境变量：

* `FF3_CIPHER_KEY`
* `FF3_CIPHER_TWEAK`
* `FF3_CIPHER_ALPHABET`

## 要求

此项目使用Golang1.22.3及更高版本进行构建和测试。

## FF3算法
## 许可证

此项目根据 [Apache 2.0许可证](https://www.apache.org/licenses/LICENSE-2.0) 授权。