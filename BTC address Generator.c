#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// Base58 Alphabet
const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// SHA-256 hashing
void sha256(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);                      // initialize SHA-256 context
    SHA256_Update(&sha256, data, len);         // hash the input data
    SHA256_Final(hash, &sha256);               // final SHA-256 hash
}

// RIPEMD-160 hashing
void ripemd160(const unsigned char *data, size_t len, unsigned char *hash) {
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);                   // initialize RIPEMD-160 context
    RIPEMD160_Update(&ripemd, data, len);      // hash the input data
    RIPEMD160_Final(hash, &ripemd);            // get the final RIPEMD-160 hash
}

// encode data to Base58
void base58_encode(unsigned char *data, size_t len, char *output) {
    int i, j, carry;
    unsigned char temp[512];
    int output_len = 0;

    // initialize the temp array
    memset(temp, 0, sizeof(temp));

    // convert to Base58
    for (i = 0; i < len; i++) {
        carry = data[i];
        for (j = 0; j < output_len; j++) {
            carry += (temp[j] << 8);
            temp[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            temp[output_len++] = carry % 58;
            carry /= 58;
        }
    }

    // handle leading zeros
    for (i = 0; i < len && data[i] == 0; i++) {
        output[i] = BASE58_ALPHABET[0];
    }

    // convert the temp array to Base58 characters
    for (j = output_len - 1; j >= 0; j--) {
        output[i++] = BASE58_ALPHABET[temp[j]];
    }

    output[i] = '\0';  // null-terminate the output string
}

// generate a Bitcoin address
void generate_bitcoin_address() {
    // Step 1: generate EC key pair (secp256k1 curve)
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (ec_key == NULL) {
        fprintf(stderr, "Error creating EC key\n");
        return;
    }
    if (EC_KEY_generate_key(ec_key) != 1) {
        fprintf(stderr, "Error generating EC key\n");
        EC_KEY_free(ec_key);
        return;
    }

    // Step 2: get public key in uncompressed form
    unsigned char *pub_key = NULL;
    int pub_key_len = i2o_ECPublicKey(ec_key, &pub_key);
    if (pub_key_len == 0) {
        fprintf(stderr, "Error getting public key\n");
        EC_KEY_free(ec_key);
        return;
    }

    // Step 3: do SHA-256 hashing on the public key
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    sha256(pub_key, pub_key_len, sha256_hash);

    // Step 4: do RIPEMD-160 hashing on the result of SHA-256
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    ripemd160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

    // Step 5: add version byte in front of RIPEMD-160 hash (0x00 for mainnet)
    unsigned char versioned_hash[1 + RIPEMD160_DIGEST_LENGTH];
    versioned_hash[0] = 0x00;  // Version byte for mainnet
    memcpy(versioned_hash + 1, ripemd160_hash, RIPEMD160_DIGEST_LENGTH);

    // Step 6: do SHA-256 twice on the extended RIPEMD-160 result
    unsigned char double_sha256_hash[SHA256_DIGEST_LENGTH];
    sha256(versioned_hash, sizeof(versioned_hash), double_sha256_hash);
    sha256(double_sha256_hash, SHA256_DIGEST_LENGTH, double_sha256_hash);

    // Step 7: take the first 4 bytes of the second SHA-256 hash as checksum
    unsigned char checksum[4];
    memcpy(checksum, double_sha256_hash, 4);

    // Step 8: add the 4 checksum bytes at the end of the extended RIPEMD-160 hash
    unsigned char address_bytes[1 + RIPEMD160_DIGEST_LENGTH + 4];
    memcpy(address_bytes, versioned_hash, sizeof(versioned_hash));
    memcpy(address_bytes + sizeof(versioned_hash), checksum, 4);

    // Step 9: encode the result in Base58
    char address_base58[100];  // Adjust size as needed
    base58_encode(address_bytes, sizeof(address_bytes), address_base58);

    // print the Bitcoin address
    printf("Bitcoin Address (Base58): %s\n", address_base58);

    // clean up
    EC_KEY_free(ec_key);
    OPENSSL_free(pub_key);
}

int main() {
    generate_bitcoin_address();
    return 0;
}
