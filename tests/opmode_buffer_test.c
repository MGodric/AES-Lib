#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"

static int run_roundtrip(aes_backend_t backend, aes_opmode_t mode,
                         const uint8_t *pt, size_t pt_len) {
    aes_core_context core;
    aes_op_context op;
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t ct[128];
    uint8_t dec[128];
    size_t ct_len = sizeof(ct);
    size_t dec_len = sizeof(dec);
    int rc;

    rc = CoreInit(&core);
    if (rc != CORE_OK) return 1;
    rc = CoreSetBackend(&core, backend);
    if (rc != CORE_OK) return 1;
    rc = CoreSetKey(&core, key, AES_128);
    if (rc != CORE_OK) return 1;

    rc = OpInit(&op);
    if (rc != OPMODE_OK) return 1;
    rc = OpSetMode(&op, mode);
    if (rc != OPMODE_OK) return 1;
    if ((mode == MODE_CBC) || (mode == MODE_CFB)) {
        rc = OpSetIV(&op, iv);
        if (rc != OPMODE_OK) return 1;
    }

    rc = OpEncryptBuffer(&core, &op, pt, pt_len, ct, &ct_len);
    if (rc != OPMODE_OK) return 1;

    if (mode == MODE_CFB) {
        if (ct_len != pt_len) return 1;
    } else {
        // PKCS#7: ciphertext length must be block aligned and strictly larger than plaintext when plaintext is aligned.
        if ((ct_len % 16) != 0) return 1;
        if ((pt_len % 16) == 0 && ct_len != pt_len + 16) return 1;
        if ((pt_len % 16) != 0 && ct_len != pt_len + (16 - (pt_len % 16))) return 1;
    }

    rc = OpDecryptBuffer(&core, &op, ct, ct_len, dec, &dec_len);
    if (rc != OPMODE_OK) return 1;
    if (dec_len != pt_len) return 1;
    if (memcmp(dec, pt, pt_len) != 0) return 1;
    return 0;
}

int main(void) {
    static const uint8_t msg31[31] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e
    };
    static const uint8_t msg32[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };

    if (run_roundtrip(AES_BACKEND_SBOX, MODE_ECB, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_SBOX, MODE_ECB, msg32, sizeof(msg32)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_SBOX, MODE_CBC, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_SBOX, MODE_CBC, msg32, sizeof(msg32)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_SBOX, MODE_CFB, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_SBOX, MODE_CFB, msg32, sizeof(msg32)) != 0) return 1;

    if (run_roundtrip(AES_BACKEND_LUT, MODE_ECB, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_LUT, MODE_ECB, msg32, sizeof(msg32)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_LUT, MODE_CBC, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_LUT, MODE_CBC, msg32, sizeof(msg32)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_LUT, MODE_CFB, msg31, sizeof(msg31)) != 0) return 1;
    if (run_roundtrip(AES_BACKEND_LUT, MODE_CFB, msg32, sizeof(msg32)) != 0) return 1;

    printf("ALL OPMODE BUFFER TESTS PASSED (ECB/CBC/CFB, SBOX/LUT)\n");
    return 0;
}
