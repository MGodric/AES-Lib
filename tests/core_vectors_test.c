#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"

typedef struct {
    const char *name;
    aes_variation variant;
    uint8_t key[32];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
} aes_known_vector_t;

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int run_one(const aes_known_vector_t *vec, aes_backend_t backend) {
    aes_core_context ctx;
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    int rc;
    const char *backend_name = (backend == AES_BACKEND_LUT) ? "LUT" : "SBOX";

    rc = CoreInit(&ctx);
    if (rc != CORE_OK) {
        printf("[%s][%s] CoreInit failed: %d\n", vec->name, backend_name, rc);
        return 1;
    }

    rc = CoreSetBackend(&ctx, backend);
    if (rc != CORE_OK) {
        printf("[%s][%s] CoreSetBackend failed: %d\n", vec->name, backend_name, rc);
        return 1;
    }

    rc = CoreSetKey(&ctx, vec->key, vec->variant);
    if (rc != CORE_OK) {
        printf("[%s][%s] CoreSetKey failed: %d\n", vec->name, backend_name, rc);
        return 1;
    }

    rc = CoreEncrypt(&ctx, vec->plaintext, enc);
    if (rc != CORE_OK) {
        printf("[%s][%s] CoreEncrypt failed: %d\n", vec->name, backend_name, rc);
        return 1;
    }
    if (memcmp(enc, vec->ciphertext, 16) != 0) {
        printf("[%s][%s] encrypt mismatch\nexpected: ", vec->name, backend_name);
        print_hex(vec->ciphertext, 16);
        printf("actual  : ");
        print_hex(enc, 16);
        return 1;
    }

    rc = CoreDecrypt(&ctx, vec->ciphertext, dec);
    if (rc != CORE_OK) {
        printf("[%s][%s] CoreDecrypt failed: %d\n", vec->name, backend_name, rc);
        return 1;
    }
    if (memcmp(dec, vec->plaintext, 16) != 0) {
        printf("[%s][%s] decrypt mismatch\nexpected: ", vec->name, backend_name);
        print_hex(vec->plaintext, 16);
        printf("actual  : ");
        print_hex(dec, 16);
        return 1;
    }

    printf("[%s][%s] PASS\n", vec->name, backend_name);
    return 0;
}

int main(void) {
    const aes_known_vector_t vectors[] = {
        {
            .name = "AES-128",
            .variant = AES_128,
            .key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            },
            .plaintext = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            },
            .ciphertext = {
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
            }
        },
        {
            .name = "AES-192",
            .variant = AES_192,
            .key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
            },
            .plaintext = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            },
            .ciphertext = {
                0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91
            }
        },
        {
            .name = "AES-256",
            .variant = AES_256,
            .key = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            },
            .plaintext = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            },
            .ciphertext = {
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89
            }
        }
    };

    const size_t n = sizeof(vectors) / sizeof(vectors[0]);
    for (size_t i = 0; i < n; i++) {
        if (run_one(&vectors[i], AES_BACKEND_SBOX) != 0) {
            return 1;
        }
        if (run_one(&vectors[i], AES_BACKEND_LUT) != 0) {
            return 1;
        }
    }

    printf("ALL CORE VECTOR TESTS PASSED (SBOX + LUT)\n");
    return 0;
}
