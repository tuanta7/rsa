# RSA CLI Tool

A command-line utility for RSA key conversion and manipulation.

## Overview

RSA-Tools provides easy-to-use commands for converting RSA keys between different formats, including PEM, DER, and JWK (
JSON Web Key). This tool is particularly useful for developers working with authentication systems, cryptography, or
security applications.

## Installation

```shell
go install https://github.com/tuanta7/rsa@latest
```

Or clone and build from source:

```shell
git clone https://github.com/tuanta7/rsa@latest
cd rsa
go build -o rsa .
```

## Usage

Supported Formats

- DER (PKCS#1)
- PEM (PKCS#1)
- JWK (JSON Web Key)

### Key Generation

```shell
# Generate a 2048-bit RSA key pair
rsa generate --bits 2048 ./keys
```

### Convert RSA Keys

Convert between different key formats:

```shell
# Convert PEM to JWK
rsa convert --output-format jwk --key-file private.pem

# Convert DER to PEM
rsa convert --output-format pem --input public.der
```

## TODO

- Support PKCS#8 format
- Add key validation commands
- Implement RSA encryption/decryption

## Cobra Debug Tutorial

- [Cobra](https://cobra.dev/)

