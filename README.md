# RSA-Tools

A command-line utility for RSA key conversion and manipulation.

## Overview

RSA-Tools provides easy-to-use commands for converting RSA keys between different formats, including PEM, DER, and JWK (
JSON Web Key). This tool is particularly useful for developers working with authentication systems, cryptography, or
security applications.
Installation

## Installation

```shell
go install gitlab.com/tuanta02/rsa-tools@latest
```

Or clone and build from source:

```shell
git clone https://gitlab.com/tuanta02/rsa-tools.git
cd rsa-tools
go build -o rsa-tools .
```

## Usage

Supported Formats

- DER (PKCS#1)
- PEM (PKCS#1)
- JWK (JSON Web Key)

### Key Generation

```shell
# Generate a 2048-bit RSA key pair
rsa-tools generate --bits 2048 --output-dir ./keys
```

### Convert RSA Keys

Convert between different key formats:

```shell
# Convert PEM to JWK
rsa-tools convert --input private.pem --output-format jwk

# Convert DER to Base64
rsa-tools convert --input public.der --output-format base64
```

## TODO

- Support PKCS#8 format
- Add key validation commands
- Implement key encryption/decryption

## Cobra Debug Tutorial

- [Cobra](https://cobra.dev/)

