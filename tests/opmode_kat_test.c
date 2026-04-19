#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t) ((hi << 4) | lo);
    }
    return 0;
}

static int run_one_mode(aes_backend_t backend, aes_opmode_t mode,
                        const uint8_t key[16], const uint8_t iv[16],
                        const uint8_t *pt, size_t pt_len,
                        const uint8_t *expected_ct_no_pad, size_t expected_ct_len) {
    aes_core_context core;
    aes_op_context op;
    uint8_t ct[128] = {0};
    uint8_t dec[128] = {0};
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
    if (mode != MODE_ECB) {
        rc = OpSetIV(&op, iv);
        if (rc != OPMODE_OK) return 1;
    }

    rc = OpEncryptBuffer(&core, &op, pt, pt_len, ct, &ct_len);
    if (rc != OPMODE_OK) return 1;

    if (mode == MODE_CFB) {
        if (ct_len != expected_ct_len) return 1;
    } else {
        if (ct_len != expected_ct_len + 16) return 1;
    }
    if (memcmp(ct, expected_ct_no_pad, expected_ct_len) != 0) return 1;

    rc = OpDecryptBuffer(&core, &op, ct, ct_len, dec, &dec_len);
    if (rc != OPMODE_OK) return 1;
    if (dec_len != pt_len) return 1;
    if (memcmp(dec, pt, pt_len) != 0) return 1;
    return 0;
}

int main(void) {
    // NIST SP 800-38A AES-128 example vectors (ECB/CBC/CFB128), 4 blocks.
    static const char *key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    static const char *iv_hex = "000102030405060708090a0b0c0d0e0f";
    static const char *pt_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    static const char *ecb_ct_hex =
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4";
    static const char *cbc_ct_hex =
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7";
    static const char *cfb_ct_hex =
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6";

    uint8_t key[16], iv[16], pt[64], ecb_ct[64], cbc_ct[64], cfb_ct[64];
    if (hex_to_bytes(key_hex, key, sizeof(key)) != 0) return 1;
    if (hex_to_bytes(iv_hex, iv, sizeof(iv)) != 0) return 1;
    if (hex_to_bytes(pt_hex, pt, sizeof(pt)) != 0) return 1;
    if (hex_to_bytes(ecb_ct_hex, ecb_ct, sizeof(ecb_ct)) != 0) return 1;
    if (hex_to_bytes(cbc_ct_hex, cbc_ct, sizeof(cbc_ct)) != 0) return 1;
    if (hex_to_bytes(cfb_ct_hex, cfb_ct, sizeof(cfb_ct)) != 0) return 1;

    for (int backend = AES_BACKEND_SBOX; backend <= AES_BACKEND_LUT; backend++) {
        const char *bname = backend == AES_BACKEND_SBOX ? "SBOX" : "LUT";
        if (run_one_mode((aes_backend_t) backend, MODE_ECB, key, iv, pt, sizeof(pt), ecb_ct, sizeof(ecb_ct)) != 0) {
            printf("[KAT][%s][ECB] FAIL\n", bname);
            return 1;
        }
        if (run_one_mode((aes_backend_t) backend, MODE_CBC, key, iv, pt, sizeof(pt), cbc_ct, sizeof(cbc_ct)) != 0) {
            printf("[KAT][%s][CBC] FAIL\n", bname);
            return 1;
        }
        if (run_one_mode((aes_backend_t) backend, MODE_CFB, key, iv, pt, sizeof(pt), cfb_ct, sizeof(cfb_ct)) != 0) {
            printf("[KAT][%s][CFB] FAIL\n", bname);
            return 1;
        }
        printf("[KAT][%s] ECB/CBC/CFB PASS\n", bname);
    }

    printf("ALL OPMODE KAT TESTS PASSED\n");
    return 0;
}
