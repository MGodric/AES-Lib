#include <stdio.h>
#include <string.h>
#include "aes.h"

typedef struct {
    const char *name;
    aes_variation variant;
    uint8_t key[32];
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
} core_vector_t;

static void PrintHex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int run_core_tests(void) {
    const core_vector_t vectors[] = {
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

    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        for (int backend = AES_BACKEND_SBOX; backend <= AES_BACKEND_LUT; backend++) {
            aes_core_context core;
            uint8_t enc[16] = {0};
            uint8_t dec[16] = {0};
            if (CoreInit(&core) != CORE_OK) return 1;
            if (CoreSetBackend(&core, (aes_backend_t) backend) != CORE_OK) return 1;
            if (CoreSetKey(&core, vectors[i].key, vectors[i].variant) != CORE_OK) return 1;
            if (CoreEncrypt(&core, vectors[i].plaintext, enc) != CORE_OK) return 1;
            if (memcmp(enc, vectors[i].ciphertext, 16) != 0) return 1;
            if (CoreDecrypt(&core, vectors[i].ciphertext, dec) != CORE_OK) return 1;
            if (memcmp(dec, vectors[i].plaintext, 16) != 0) return 1;
            printf("[CORE][%s][%s] PASS\n", vectors[i].name,
                   backend == AES_BACKEND_SBOX ? "SBOX" : "LUT");
        }
    }

    return 0;
}

static int run_opmode_demo(void) {
    aes_core_context core;
    aes_op_context op;
    const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t plaintext[] = "hello aes single-file library";
    uint8_t ciphertext[128] = {0};
    uint8_t recovered[128] = {0};
    size_t ct_len = sizeof(ciphertext);
    size_t pt_len = sizeof(recovered);

    if (CoreInit(&core) != CORE_OK) return 1;
    if (CoreSetBackend(&core, AES_BACKEND_LUT) != CORE_OK) return 1;
    if (CoreSetKey(&core, key, AES_128) != CORE_OK) return 1;

    if (OpInit(&op) != OPMODE_OK) return 1;
    if (OpSetMode(&op, MODE_CBC) != OPMODE_OK) return 1;
    if (OpSetIV(&op, iv) != OPMODE_OK) return 1;

    if (OpEncryptBuffer(&core, &op, plaintext, sizeof(plaintext) - 1, ciphertext, &ct_len) != OPMODE_OK) return 1;
    if (OpDecryptBuffer(&core, &op, ciphertext, ct_len, recovered, &pt_len) != OPMODE_OK) return 1;
    if (pt_len != sizeof(plaintext) - 1) return 1;
    if (memcmp(plaintext, recovered, pt_len) != 0) return 1;

    printf("Ciphertext: ");
    PrintHex(ciphertext, ct_len);
    printf("Recovered : %.*s\n", (int) pt_len, (const char *) recovered);
    printf("[OPMODE] Demo PASS\n");
    return 0;
}

int main(void) {
    if (run_core_tests() != 0) {
        printf("[CORE] FAIL\n");
        return 1;
    }
    if (run_opmode_demo() != 0) {
        printf("[OPMODE] FAIL\n");
        return 1;
    }
    printf("ALL TESTS PASS\n");
    return 0;
}
