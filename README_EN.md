# golang-fpe

[中文](./README.md)

* Refer from [mysto/python-fpe](https://github.com/mysto/python-fpe?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=2)
* Algorithm Explain: [保形加密](https://knowuv.com/blog/fpe_encryption?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=2)
* Mathematical Basics: [Galois Field](https://knowuv.com/blog/galois_field?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=2)
* Application: [URL Shorter](https://knowuv.com/blog/short-link?utm_source=github&utm_medium=readme&utm_campaign=sl&utm_id=2)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Code Example

The example code below uses the default domain [0-9] and can help you get started.

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
	cipher, err := ff3.NewFF3Cipher(key, tweak, 10)
	if err != nil {
		log.Fatalf("Failed to create FF3 cipher: %v", err)
	}

	plaintext := "20241101"
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt plaintext: %v", err)
	}
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext: %v", err)
	}

	fmt.Printf("%s -> %s -> %s\n", plaintext, ciphertext, decrypted)
}
```

# FF3 - Format Preserving Encryption in Golang

An implementation of the NIST approved FF3 and FF3-1 Format Preserving Encryption (FPE) algorithms in Python.

This package implements the FF3 algorithm for Format Preserving Encryption as described in the March 2016 NIST publication 800-38G _Methods for Format-Preserving Encryption_,
and revised on February 28th, 2019 with a draft update for FF3-1.

* [NIST Recommendation SP 800-38G (FF3)](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)
* [NIST Recommendation SP 800-38G Revision 1 (FF3-1)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf)

Changes to minimum domain size and revised tweak length have been implemented in this package with
support for both 64-bit and 56-bit tweaks. NIST has only published official test vectors for 64-bit tweaks,
but draft ACVP test vectors have been used for testing FF3-1. It is expected the final
NIST standard will provide updated test vectors with 56-bit tweak lengths.

## Installation

`go get github.com/dusty-cjh/golang-fpe`

## Usage

FF3 is a Feistel cipher, and Feistel ciphers are initialized with a radix representing an alphabet. The number of
characters in an alphabet is called the _radix_.
The following radix values are typical:

* radix 10: digits 0..9
* radix 36: alphanumeric 0..9, a-z
* radix 62: alphanumeric 0..9, a-z, A-Z

Special characters and international character sets, such as those found in UTF-8, are supported by specifying a custom alphabet.
Also, all elements in a plaintext string share the same radix. Thus, an identification number that consists of an initial letter followed
by 6 digits (e.g. A123456) cannot be correctly encrypted by FPE while preserving this convention.

Input plaintext has maximum length restrictions based upon the chosen radix (2 * floor(96/log2(radix))):

* radix 10: 56
* radix 36: 36
* radix 62: 32

To work around string length, its possible to encode longer text in chunks.

The key length must be 128, 192, or 256 bits in length. The tweak is 7 bytes (FF3-1) or 8 bytes for the origingal FF3.

As with any cryptographic package, managing and protecting the key(s) is crucial. The tweak is generally not kept secret.
This package does not store the key in memory after initializing the cipher.

## Custom alphabets

Custom alphabets up to 256 characters are supported. To use an alphabet consisting of the uppercase letters A-F (radix=6), we can continue
from the above code example with:

Use these environment variables:

* `FF3_CIPHER_KEY`
* `FF3_CIPHER_TWEAK`
* `FF3_CIPHER_ALPHABET`

## Requires

This project was built and tested with Golang1.22.3 and later versions.

## License

This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).
