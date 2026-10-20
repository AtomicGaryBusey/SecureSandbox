#!/usr/bin/env python3
"""Convert one unencrypted PKCS#8 private key from stdin to OpenSSH on stdout."""

import sys

from cryptography.hazmat.primitives import serialization


def main() -> None:
    source = sys.stdin.buffer.read()
    key = serialization.load_pem_private_key(source, password=None)
    converted = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sys.stdout.buffer.write(converted)


if __name__ == "__main__":
    main()
