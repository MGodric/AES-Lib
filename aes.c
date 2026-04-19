#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30,
    0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
    0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2,
    0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
    0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
    0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2,
    0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53,
    0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
    0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
    0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
    0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
    0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
    0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46,
    0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
    0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65,
    0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
    0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b,
    0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
    0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
    0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89,
    0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t invsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf,
    0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3,
    0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43,
    0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42,
    0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9,
    0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1,
    0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c,
    0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15,
    0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
    0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
    0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
    0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc,
    0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2,
    0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1,
    0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62,
    0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78,
    0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
    0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec,
    0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0,
    0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb,
    0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04,
    0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

int CoreInit(aes_core_context *ctx) {
    if (ctx == NULL) {
        return CORE_ERR_ARG;
    } else {
        memset(ctx->key, 0, sizeof(ctx->key));
        ctx->key_size = 0;
        ctx->backend = AES_BACKEND_SBOX;
        memset(ctx->round_key_list, 0,
               sizeof(ctx->round_key_list));
        ctx->lut_decry_roundkeylist = NULL;
        ctx->te = NULL;
        ctx->td = NULL;
        ctx->has_lut = 0;
        return CORE_OK;
    }
}

int CoreSetBackend(aes_core_context *ctx, aes_backend_t backend) {
    if ((ctx == NULL) || ((backend != AES_BACKEND_SBOX) && (backend != AES_BACKEND_LUT))) {
        return CORE_ERR_ARG;
    }
    free(ctx->lut_decry_roundkeylist);
    free(ctx->te);
    free(ctx->td);
    switch (backend) {
        case AES_BACKEND_SBOX:
            ctx->lut_decry_roundkeylist = NULL;
            ctx->te = NULL;
            ctx->td = NULL;
            ctx->has_lut = 0;
            ctx->backend = AES_BACKEND_SBOX;
            return CORE_OK;
        case AES_BACKEND_LUT:
            ctx->lut_decry_roundkeylist = malloc(sizeof(ctx->round_key_list));
            ctx->te = malloc(4 * sizeof(*ctx->te));
            ctx->td = malloc(4 * sizeof(*ctx->td));
            if ((ctx->lut_decry_roundkeylist == NULL) || (ctx->te == NULL) || (ctx->td == NULL)) {
                ctx->backend = AES_BACKEND_SBOX;
                free(ctx->lut_decry_roundkeylist);
                free(ctx->te);
                free(ctx->td);
                ctx->has_lut = 0;
                return CORE_ERR_STATE;
            }
            ctx->backend = AES_BACKEND_LUT;
            ctx->has_lut = 1;
            return CORE_OK;
        default:
            return CORE_ERR_UNSUPPORTED;
    }
}

static void RotWord(uint8_t word[4]) {
    uint8_t temp = word[0];

    for (int i = 0; i < 3; i++)
        word[i] = word[i + 1];
    word[3] = temp;
}

static void SubWord(uint8_t word[4]) {
    for (int i = 0; i < 4; i++)
        word[i] = sbox[word[i]];
}

static void KeyExpansion(aes_core_context *ctx) {
    uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                      0x20, 0x40, 0x80, 0x1b, 0x36};
    uint8_t temp[4];
    uint8_t nr = 6 + (ctx->key_size / 4), nk = nr - 6, num_words = (nr + 1) * 4;

    for (uint8_t i = nk; i < num_words; i++) {
        memcpy(temp, (ctx->round_key_list + 4 * (i - 1)), 4);
        if (i % nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= rcon[(i / nk) - 1];
        } else if ((ctx->key_size == 32) && (i % nk == 4))
            SubWord(temp);
        for (uint8_t j = 0; j < 4; j++)
            temp[j] ^= *(ctx->round_key_list + 4 * (i - nk) + j);
        memcpy((ctx->round_key_list + 4 * i), temp, 4);
    }
}
static uint8_t GF28ConstMul(uint8_t a, uint8_t multiplicant) {
    uint8_t result = 0;
    uint8_t xtimes_a[4];

    xtimes_a[0] = a;
    for (int i = 1; i < 4; i++) {           // xtimes_a[4] is {a, 2a, 4a, 8a}
        xtimes_a[i] = xtimes_a[i - 1] << 1; // Process of a * 0x02
        if (xtimes_a[i - 1] & 0x80)
            xtimes_a[i] ^= 0x1b;
    }
    for (int i = 0; i < 4; i++) { // Process of (a * times)
        if ((multiplicant >> i) & 0x01)
            result ^= xtimes_a[i];
    }

    return result;
}
static void InvMixColumns(uint8_t state[16]) {
    uint8_t temp[4];

    for (uint8_t i = 0; i < 16; i += 4) {
        temp[0] = GF28ConstMul(state[i], 0x0e) ^ GF28ConstMul(state[i + 1], 0x0b) ^ GF28ConstMul(state[i + 2], 0x0d) ^ GF28ConstMul(state[i + 3], 0x09);
        temp[1] = GF28ConstMul(state[i], 0x09) ^ GF28ConstMul(state[i + 1], 0x0e) ^ GF28ConstMul(state[i + 2], 0x0b) ^ GF28ConstMul(state[i + 3], 0x0d);
        temp[2] = GF28ConstMul(state[i], 0x0d) ^ GF28ConstMul(state[i + 1], 0x09) ^ GF28ConstMul(state[i + 2], 0x0e) ^ GF28ConstMul(state[i + 3], 0x0b);
        temp[3] = GF28ConstMul(state[i], 0x0b) ^ GF28ConstMul(state[i + 1], 0x0d) ^ GF28ConstMul(state[i + 2], 0x09) ^ GF28ConstMul(state[i + 3], 0x0e);
        memcpy(&state[i], temp, 4);
    }
}

static void InvMixColKeyArray(aes_core_context *ctx) { // InvMixColumns on round keys for round 1 ~ (nr-1)
    uint8_t nr = 6 + (ctx->key_size / 4);
    memcpy(ctx->lut_decry_roundkeylist, ctx->round_key_list, sizeof(ctx->round_key_list));
    for (uint8_t r = 1; r < nr; r++) {
        InvMixColumns(ctx->lut_decry_roundkeylist + 16 * r);
    }
}

void TableGen(aes_core_context *ctx) { // mode 0 for Tex; mode 1 for Tdx
    for (int i = 0; i < 256; i++) {    // Generate Te0, with coefficients of (2, 1, 1, 3)
        ctx->te[0][i][0] = GF28ConstMul(sbox[i], 0x02);
        ctx->te[0][i][1] = sbox[i];
        ctx->te[0][i][2] = sbox[i];
        ctx->te[0][i][3] = GF28ConstMul(sbox[i], 0x03);
    }

    for (int i = 0; i < 256; i++) { // Generate Td0, with coefficients of (e, 9, d, b)
        ctx->td[0][i][0] = GF28ConstMul(invsbox[i], 0x0e);
        ctx->td[0][i][1] = GF28ConstMul(invsbox[i], 0x09);
        ctx->td[0][i][2] = GF28ConstMul(invsbox[i], 0x0d);
        ctx->td[0][i][3] = GF28ConstMul(invsbox[i], 0x0b);
    }

    for (int i = 1; i < 4; i++) { // Generate T1 ~ T3 from T0
        for (int j = 0; j < 256; j++) {
            for (int k = 0; k < 4; k++) { // Example: Te0:2113 -> Te1:1132 -> Te2:1321 -> Te3:3211
                ctx->te[i][j][k] = ctx->te[i - 1][j][(k + 3) % 4];
                ctx->td[i][j][k] = ctx->td[i - 1][j][(k + 3) % 4];
            }
        }
    }
}

int CoreSetKey(aes_core_context *ctx, const uint8_t *key,
               aes_variation variant) {
    if ((ctx == NULL) || (key == NULL) || ((variant != AES_128) && (variant != AES_192) && (variant != AES_256))) {
        return CORE_ERR_ARG;
    } else {
        memcpy(ctx->key, key, variant);
        ctx->key_size = variant;
        memset(ctx->round_key_list, 0, sizeof(ctx->round_key_list));
        memcpy(ctx->round_key_list, key, variant);
        switch (ctx->backend) {
            case AES_BACKEND_SBOX:
                KeyExpansion(ctx);
                return CORE_OK;
            case AES_BACKEND_LUT:
                if ((ctx->lut_decry_roundkeylist == NULL) || (ctx->te == NULL) || (ctx->td == NULL) || (ctx->has_lut == 0))
                    return CORE_ERR_STATE;
                KeyExpansion(ctx);
                InvMixColKeyArray(ctx);
                TableGen(ctx);
                return CORE_OK;
            default:
                return CORE_ERR_UNSUPPORTED;
        }
    }
}

static void AddRoundKey(uint8_t state[16], const uint8_t *round_key_list,
                        uint8_t round) {
    for (uint8_t i = 0; i < 16; i++) {
        state[i] ^= *(round_key_list + 16 * round + i);
    }
}

static void SubBytes(uint8_t state[16]) {
    for (uint8_t i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

static void ShiftRows(uint8_t state[16]) {
    uint8_t t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    t = state[2];
    uint8_t t2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t;
    state[14] = t2;

    t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

static void MixColumns(uint8_t state[16]) {
    uint8_t temp[4];

    for (uint8_t i = 0; i < 16; i += 4) {
        temp[0] = GF28ConstMul(state[i], 0x02) ^ GF28ConstMul(state[i + 1], 0x03) ^ state[i + 2] ^ state[i + 3];
        temp[1] = state[i] ^ GF28ConstMul(state[i + 1], 0x02) ^ GF28ConstMul(state[i + 2], 0x03) ^ state[i + 3];
        temp[2] = state[i] ^ state[i + 1] ^ GF28ConstMul(state[i + 2], 0x02) ^ GF28ConstMul(state[i + 3], 0x03);
        temp[3] = GF28ConstMul(state[i], 0x03) ^ state[i + 1] ^ state[i + 2] ^ GF28ConstMul(state[i + 3], 0x02);
        memcpy(&state[i], temp, 4);
    }
}

static void TableLookUp(uint8_t state[16], uint8_t table[4][256][4],
                        uint8_t mode) { // mode 0 for encrypt; mode 1
                                        // for decrypt
    uint8_t temp[16];

    if (mode == 0) {
        for (uint8_t c = 0; c < 4; c++) {
            for (uint8_t r = 0; r < 4; r++)
                temp[r + 4 * c] = table[0][state[4 * c]][r] ^ table[1][state[1 + 4 * ((c + 1) % 4)]][r] ^ table[2][state[2 + 4 * ((c + 2) % 4)]][r] ^ table[3][state[3 + 4 * ((c + 3) % 4)]][r];
        }
    } else if (mode == 1) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++)
                temp[r + 4 * c] = table[0][state[4 * c]][r] ^ table[1][state[1 + 4 * ((c + 3) % 4)]][r] ^ table[2][state[2 + 4 * ((c + 2) % 4)]][r] ^ table[3][state[3 + 4 * ((c + 1) % 4)]][r];
        }
    }
    memcpy(state, temp, 16);
}

int CoreEncrypt(const aes_core_context *ctx,
                const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out)
        return CORE_ERR_ARG;
    if ((ctx->backend != AES_BACKEND_SBOX) && (ctx->backend != AES_BACKEND_LUT))
        return CORE_ERR_UNSUPPORTED;
    if (ctx->key_size != AES_128 && ctx->key_size != AES_192 && ctx->key_size != AES_256)
        return CORE_ERR_STATE;

    uint8_t state[16];
    memcpy(state, in, 16);
    uint8_t nr = (ctx->key_size / 4) + 6;

    if (ctx->backend == AES_BACKEND_SBOX) {
        AddRoundKey(state, ctx->round_key_list, 0);
        for (uint8_t i = 1; i < nr; i++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, ctx->round_key_list, i);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, ctx->round_key_list, nr);
        memcpy(out, state, 16);
        return CORE_OK;
    } else if (ctx->backend == AES_BACKEND_LUT) {
        if ((ctx->lut_decry_roundkeylist == NULL) || (ctx->te == NULL) || (ctx->td == NULL) || (ctx->has_lut == 0))
            return CORE_ERR_STATE;
        AddRoundKey(state, ctx->round_key_list, 0);
        for (uint8_t i = 1; i < nr; i++) {
            TableLookUp(state, ctx->te, 0);
            AddRoundKey(state, ctx->round_key_list, i);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, ctx->round_key_list, nr);
        memcpy(out, state, 16);
        return CORE_OK;
    }
    return CORE_ERR_UNSUPPORTED;
}

static void InvShiftRows(uint8_t state[16]) {
    uint8_t t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;

    t = state[14];
    uint8_t t2 = state[10];
    state[14] = state[6];
    state[10] = state[2];
    state[6] = t;
    state[2] = t2;

    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

static void InvSubBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = invsbox[state[i]];
    }
}

int CoreDecrypt(const aes_core_context *ctx,
                const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out)
        return CORE_ERR_ARG;
    if ((ctx->backend != AES_BACKEND_SBOX) && (ctx->backend != AES_BACKEND_LUT))
        return CORE_ERR_UNSUPPORTED;
    if (ctx->key_size != AES_128 && ctx->key_size != AES_192 && ctx->key_size != AES_256)
        return CORE_ERR_STATE;

    uint8_t state[16];
    memcpy(state, in, 16);
    uint8_t nr = (ctx->key_size / 4) + 6;

    if (ctx->backend == AES_BACKEND_SBOX) {
        AddRoundKey(state, ctx->round_key_list, nr);
        for (uint8_t i = nr - 1; i > 0; i--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, ctx->round_key_list, i);
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, ctx->round_key_list, 0);
        memcpy(out, state, 16);
        return CORE_OK;
    } else if (ctx->backend == AES_BACKEND_LUT) {
        if ((ctx->lut_decry_roundkeylist == NULL) || (ctx->te == NULL) || (ctx->td == NULL) || (ctx->has_lut == 0))
            return CORE_ERR_STATE;
        AddRoundKey(state, ctx->lut_decry_roundkeylist, nr);
        for (uint8_t i = nr - 1; i > 0; i--) {
            TableLookUp(state, ctx->td, 1);
            AddRoundKey(state, ctx->lut_decry_roundkeylist, i);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, ctx->lut_decry_roundkeylist, 0);
        memcpy(out, state, 16);
        return CORE_OK;
    }
    return CORE_ERR_UNSUPPORTED;
}

void CorePrintKeyList(const uint8_t *round_key_list, uint8_t key_size) { // For debugging
    if (round_key_list == NULL || (key_size != AES_128 && key_size != AES_192 && key_size != AES_256)) {
        printf("CorePrintKeyList: invalid input\n");
        return;
    }

    uint8_t nr_local = 6 + (key_size / 4);
    uint8_t words = (nr_local + 1) * 4;

    for (uint8_t i = 0; i < words; i++) {
        const uint8_t *w = round_key_list + 4 * i;
        printf("%02x %02x %02x %02x\n", w[0], w[1], w[2], w[3]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
}

void CorePrintState(const uint8_t state[16]) { // For debugging
    if (state == NULL) {
        printf("CorePrintState: invalid input\n");
        return;
    }

    for (uint8_t r = 0; r < 4; r++) {
        printf("%02x %02x %02x %02x\n",
               state[r], state[r + 4], state[r + 8], state[r + 12]);
    }
    printf("\n");
}

void CorePrintLUT(const uint8_t table[4][256][4]) { // For debugging (Te or Td)
    if (table == NULL) {
        printf("CorePrintLUT: invalid input\n");
        return;
    }

    for (uint8_t i = 0; i < 4; i++) {
        printf("T%d is:\n", i);
        for (uint16_t j = 0; j < 256; j++) {
            printf("%02x%02x%02x%02x\n",
                   table[i][j][0], table[i][j][1], table[i][j][2], table[i][j][3]);
        }
        printf("\n");
    }
}

int OpInit(aes_op_context *opctx) {
    if (opctx == NULL) {
        return OPMODE_ERR_ARG;
    } else {
        memset(opctx->iv, 0, sizeof(opctx->iv));
        opctx->opmode = MODE_ECB;
        return OPMODE_OK;
    }
}
int OpSetMode(aes_op_context *opctx, aes_opmode_t mode) {
    if (opctx == NULL)
        return OPMODE_ERR_ARG;
    if ((opctx->opmode != MODE_ECB) && (opctx->opmode != MODE_ECB) && (opctx->opmode != MODE_CFB))
        return OPMODE_ERR_UNSUPPORTED;
    memset(opctx->iv, 0, sizeof(opctx->iv));
    return OPMODE_OK;
}
int OpSetIV(aes_op_context *opctx, const uint8_t iv[16]) {
    if ((opctx == NULL) || (iv == NULL))
        return OPMODE_ERR_ARG;
    memcpy(opctx->iv, iv, sizeof(iv));
    return OPMODE_OK;
}

int OpEncryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);

int OpDecryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);