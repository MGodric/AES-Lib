#ifndef AES_LIB_AES_H
#define AES_LIB_AES_H

#include <stdint.h>

typedef enum {
    CORE_OK = 0,
    CORE_ERR_ARG = -1,
    CORE_ERR_STATE = -2,
    CORE_ERR_UNSUPPORTED = -3
} aes_core_state_t;

typedef enum {
    AES_BACKEND_SBOX,
    AES_BACKEND_LUT
} aes_backend_t;

typedef enum {
    AES_128 = 16,
    AES_192 = 24,
    AES_256 = 32
} aes_variation;

typedef struct {
    uint8_t key[32];
    uint8_t key_size;
    aes_backend_t backend;
    uint8_t round_key_list[240];
    uint8_t *lut_decry_roundkeylist;
    uint8_t (*te)[256][4];
    uint8_t (*td)[256][4];
    uint8_t has_lut;
} aes_core_context;

int CoreInit(aes_core_context *ctx);
int CoreSetBackend(aes_core_context *ctx, aes_backend_t backend);
int CoreSetKey(aes_core_context *ctx, const uint8_t *key, aes_variation variant);

int CoreEncrypt(const aes_core_context *ctx, const uint8_t in[16], uint8_t out[16]);
int CoreDecrypt(const aes_core_context *ctx, const uint8_t in[16], uint8_t out[16]);

typedef enum {
    OPMODE_OK = 0,
    OPMODE_ERR_ARG = -1,
    OPMODE_ERR_STATE = -2,
    OPMODE_ERR_UNSUPPORTED = -3
} aes_opmode_state_t;

typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB
} aes_opmode_t;

typedef struct {
    uint8_t iv[16];
    aes_opmode_t opmode;
} aes_op_context;

int OpInit(aes_op_context *opctx);
int OpSetMode(aes_op_context *opctx, aes_opmode_t mode);
int OpSetIV(aes_op_context *opctx, const uint8_t iv[16]);

int OpEncryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);

int OpDecryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);
#endif // AES_LIB_AES_H
