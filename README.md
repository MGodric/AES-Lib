# AES-Lib

This repository contains a C library for the Advanced Encryption Standard (AES) algorithm. It supports key sizes of 128, 192, and 256 bits. 

The primary purpose of this library is educational. The computation has been verified to be correct, but **no security measures have been implemented**. Therefore, it is advised **not to use this library directly for sensitive applications**.

## Features

- Supports AES-128, AES-192, and AES-256.
- Programmed according to the NIST-197 standard process. No special tricks are used, keeping the code intuitively readable.
- Includes two implementations: S-Box and lookup-table (T-Table/T-Box). The lookup tables are generated on-the-fly.

## Usage

A test case is programmed in "main.c".

The encrypting and decrypting functions of the two implementations use the same parameters:

```c
void EncryptSBox(uint8_t plaintext[16], uint8_t key[], uint8_t ciphertext[16], uint8_t nr);
void DecryptSBox(uint8_t ciphertext[16], uint8_t key[], uint8_t plaintext[16], uint8_t nr);

void EncryptTable(uint8_t plaintext[16], uint8_t key[], uint8_t ciphertext[16], uint8_t nr);
void DecryptTable(uint8_t ciphertext[16], uint8_t key[], uint8_t plaintext[16], uint8_t nr);
```

Modify **the size of key[]** and **Nr** to use different key lengths in AES. This library does not perform any input validation. Please ensure that the input data and key sizes are appropriate for the selected AES variant (128, 192, or 256 bits).

| Variant |     Key Length      | Rounds (Nr) |
| :-----: | :-----------------: | :---------: |
| AES-128 | 16 Bytes (128 Bits) |     10      |
| AES-192 | 24 Bytes (192 Bits) |     12      |
| AES-256 | 32 Bytes (256 Bits) |     14      |

Functions for debugging.

```c
void PrintState(uint8_t state[4][4]);
void PrintKeyArray(uint8_t keyarray[][4], uint8_t nr);
void PrintTable(uint8_t table[4][256][4]);
```
