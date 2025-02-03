# Bitcoin-Address-Generator-in-C
I will agree that this project was tough for me, many new things i used that i might still lack a bit of understanding of but i pulled it off, Yeah !

This project implements a Bitcoin address generator using the secp256k1 elliptic curve, the standard curve used in Bitcoin. The program generates a Bitcoin address by performing the following steps:

EC Key Pair Generation: Generates a public/private key pair using the secp256k1 elliptic curve.
SHA-256 Hashing: The public key is hashed using the SHA-256 algorithm.
RIPEMD-160 Hashing: The resulting SHA-256 hash is further hashed using the RIPEMD-160 algorithm to produce a shorter public key hash.
Version Byte: A version byte (0x00) is added to the front of the public key hash, indicating that it is for the Bitcoin mainnet.
Double SHA-256 Checksum: The address data (versioned public key hash) undergoes a double SHA-256 hashing, and the first 4 bytes of the result are used as a checksum to ensure the address is valid.
Base58 Encoding: The address data, along with the checksum, is encoded in Base58 to generate the final Bitcoin address. This encoding makes the address more human-readable and reduces errors when copying.

Features:
Utilizes OpenSSL libraries for cryptographic operations such as elliptic curve key generation and hashing.
Outputs a Bitcoin address in Base58 format, which is the standard address format used in Bitcoin transactions.

You must have OpenSSL installed 
Compilation - gcc -o bitcoin_address_generator bitcoin_address_generator.c -lssl -lcrypto
