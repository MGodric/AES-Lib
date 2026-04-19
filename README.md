# AES-Lib

A small AES library in C for learning and experimentation.

Current design is a **single-file library** style:
- Public API: `aes.h`
- Implementation: `aes.c`

Supports:
- AES-128 / AES-192 / AES-256
- Two backends: `AES_BACKEND_SBOX` and `AES_BACKEND_LUT`
- Operation modes (buffer API): `ECB`, `CBC`, `CFB`

## Security Notice

This project is for educational use.
It is functionally tested, but not hardened for production security (no side-channel resistance, no secure memory wipe policy, etc.).
Do not use directly in sensitive production systems.

## Integrate Into Your Project

Copy `aes.h` and `aes.c` into your project, then compile/link `aes.c`.

Example:

```bash
cc -std=c11 -O2 -I. your_app.c aes.c -o your_app
```

## API Overview

### 1) Core context (single-block AES)

```c
int CoreInit(aes_core_context *ctx);
int CoreSetBackend(aes_core_context *ctx, aes_backend_t backend);
int CoreSetKey(aes_core_context *ctx, const uint8_t *key, aes_variation variant);

int CoreEncrypt(const aes_core_context *ctx, const uint8_t in[16], uint8_t out[16]);
int CoreDecrypt(const aes_core_context *ctx, const uint8_t in[16], uint8_t out[16]);
```

Recommended call order:
1. `CoreInit`
2. `CoreSetBackend`
3. `CoreSetKey`
4. `CoreEncrypt` / `CoreDecrypt`

### 2) Op context (multi-block buffer API)

```c
int OpInit(aes_op_context *opctx);
int OpSetMode(aes_op_context *opctx, aes_opmode_t mode);
int OpSetIV(aes_op_context *opctx, const uint8_t iv[16]);

int OpEncryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);

int OpDecryptBuffer(const aes_core_context *corectx, const aes_op_context *opctx,
                    const uint8_t *in, size_t in_len,
                    uint8_t *out, size_t *out_len);
```

Mode behavior:
- `MODE_ECB`: PKCS#7 padding on encrypt, PKCS#7 unpadding on decrypt.
- `MODE_CBC`: PKCS#7 padding on encrypt, PKCS#7 unpadding on decrypt, requires IV.
- `MODE_CFB`: stream-style, no PKCS#7 padding, output length equals input length, requires IV.

`out_len` contract:
- Input: capacity of output buffer.
- Output: actual bytes written.
- If capacity is insufficient, function returns error and writes required length to `*out_len`.

## Call Flow

### A) Core-only (single block, 16 bytes)

Use this path when you only need AES block encryption/decryption and will manage mode/padding yourself.

1. Declare a context:
   - `aes_core_context core;`
2. Initialize:
   - `CoreInit(&core);`
3. Select backend:
   - `CoreSetBackend(&core, AES_BACKEND_SBOX)` or `AES_BACKEND_LUT`
4. Set key and variant:
   - `CoreSetKey(&core, key, AES_128 / AES_192 / AES_256);`
5. Encrypt/decrypt one 16-byte block:
   - `CoreEncrypt(&core, in16, out16);`
   - `CoreDecrypt(&core, in16, out16);`

Notes:
- `CoreEncrypt/CoreDecrypt` process exactly 16 bytes each call.
- Call `CoreSetKey` again if key or key size changes.

### B) Core + OpMode (multi-block buffer API)

Use this path when you want mode handling (`ECB/CBC/CFB`) and padding behavior handled by the library.

1. Prepare core:
   - `CoreInit(&core);`
   - `CoreSetBackend(&core, ...);`
   - `CoreSetKey(&core, key, variant);`
2. Prepare op context:
   - `OpInit(&op);`
   - `OpSetMode(&op, MODE_ECB / MODE_CBC / MODE_CFB);`
   - If mode needs IV (`CBC`/`CFB`): `OpSetIV(&op, iv16);`
3. Encrypt buffer:
   - Set `out_len = output_buffer_capacity`
   - Call `OpEncryptBuffer(&core, &op, in, in_len, out, &out_len);`
4. Decrypt buffer:
   - Set `plain_len = output_buffer_capacity`
   - Call `OpDecryptBuffer(&core, &op, in, in_len, out, &plain_len);`

Mode-specific behavior:
- `MODE_ECB`: PKCS#7 pad/unpad.
- `MODE_CBC`: PKCS#7 pad/unpad, requires IV.
- `MODE_CFB`: no PKCS#7, output length equals input length, requires IV.

## Minimal Example

The minimal runnable example is in `examples/basic_demo.c`.

Typical usage flow:

1. `CoreInit`
2. `CoreSetBackend`
3. `CoreSetKey`
4. `OpInit`
5. `OpSetMode` (and `OpSetIV` if mode needs IV)
6. `OpEncryptBuffer`
7. `OpDecryptBuffer`

For complete compilable code, see `examples/basic_demo.c`.

## Tests

Core vectors (AES-128/192/256, SBOX/LUT):

```bash
cc -std=c11 -Wall -Wextra -Wpedantic -I. tests/core_vectors_test.c aes.c -o /tmp/core_vectors_test
/tmp/core_vectors_test
```

Op-mode roundtrip tests (ECB/CBC/CFB, SBOX/LUT):

```bash
cc -std=c11 -Wall -Wextra -Wpedantic -I. tests/opmode_buffer_test.c aes.c -o /tmp/opmode_buffer_test
/tmp/opmode_buffer_test
```

Op-mode KAT tests (NIST SP 800-38A ECB/CBC/CFB128 vectors, AES-128, SBOX/LUT):

```bash
cc -std=c11 -Wall -Wextra -Wpedantic -I. tests/opmode_kat_test.c aes.c -o /tmp/opmode_kat_test
/tmp/opmode_kat_test
```

With CMake/CTest:

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```
