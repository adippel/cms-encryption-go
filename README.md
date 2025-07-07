# CMS Encryption in Go: Secure Data with OpenSSL and CGO

This project demonstrates how to perform CMS (Cryptographic Message Syntax) encryption in Go using OpenSSL’s `libcrypto`
via CGO. It includes a simple command-line tool that encrypts a message for a recipient using their X.509 certificate,
producing a `.p7m` CMS/PKCS#7 message.

📖 This is companion code for the blog post:
[CMS Encryption in Go: Secure Data with OpenSSL and CGO](https://alexdippel.de/2025/07/cms-encryption-in-go-secure-data-with-openssl-and-cgo/)

## Features

- Encrypt messages using CMS and AES-GCM
- X.509 certificate parsing and recipient management
- PEM-formatted CMS output (`.p7m`)
- OpenSSL error handling in Go
- Wrapping C macros for CGO compatibility

## Development setup

This example relies on CGO and the OpenSSL C libraries. CGO has support for `pkg-config` to correctly discover required
paths for the compiler and linker. Ensure that the following is installed on your system:

* `pkg-config`
* `openssl` and its header files

Ensure OpenSSL >= 3.0 is installed on your system and can be discovered using `pkg-config`:

```bash
pkg-config --modversion openssl
```

**A note for macOS users**

macOS' native OpenSSL distribution cannot be symlinked due to restrictions on macOS. Install OpenSSL separatly for
example using `brew`. To allow `pkg-config` to find the installation, ensure to set the following environment variable (
change path if your are not using brew):

```bash
export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig"
```

To test your installation, run and check the output that should be similar to the shown output:

```bash
pkg-config --cflags --libs openssl
-I/opt/homebrew/Cellar/openssl@3/3.4.1/include -L/opt/homebrew/Cellar/openssl@3/3.4.1/lib -lssl -lcrypto
```

## Example

The `main.go` contains small CLI examples demonstrating the usage of the library. To start encrypting,
generate a new EC key and a self-signed certificate as follows:

```bash
CMS_KEY=ec-private-key.pem                                                                            
CMS_CERT=ec-test-cert.pem

openssl req -new -newkey ec -pkeyopt group:prime256v1 -noenc -keyout $CMS_KEY \
        -out $CMS_CERT -outform PEM -x509 -days 365 \
        -subj "/O=alexdippel.de laboratory/OU=CMS Test laboratory/CN=test-recipient" \
        -addext keyUsage=critical,digitalSignature,keyAgreement
```

Then, we can encrypt the message for the certificate:

```bash
go run ./main.go -cert "$CMS_CERT" -out ./encrypted.p7m -message "Hello  Test"
```

The encrypted message is saved in the file `encrypted.p7m`. To view the CMS structure, use the following command:

```bash
openssl cms -cmsout -inform PEM -in ./encrypted.p7m -print
```

To decrypt the message with the corresponding private key, use the following command:

```bash
openssl cms -decrypt -in ./encrypted.p7m -inform PEM -recip $CMS_CERT -inkey $CMS_KEY
```