# AES-Lib

This repository contains a C library for the Advanced Encryption Standard (AES) algorithm with several operation modes of block ciphers. Supports key sizes of 128, 192, and 256 bits.

The primary purpose of this library is educational. The computation has been verified to be correct, but **no security measures have been implemented**. Therefore, it is advised **not to use this library directly for sensitive applications**.

## Features

- Supports AES-128, AES-192, and AES-256.
- Programmed and tested according to the NIST-197 and NIST Special Publication 800-38A standard documents. 
- Includes two implementations: S-Box and lookup-table (T-Table/T-Box). The lookup tables are generated on-the-fly.
- Operation modes of the block cipher, such as ECB, CBC. Other modes to be implemented later on.

## Usage

### test.h

Test cases with test vectors from NIST documents are programmed in "test.c".

### aes.h

The encrypting and decrypting functions of the two implementations use the same parameters:

```c
void SetKey(uint8_t key[], uint8_t size); //Assign cipher key and its size (Must be called before en/decryptions)
void SetLUTMode(void); //Enter LUT cipher mode (S-Box mode in default when not calling this function)
void QuitLUTMode(void); //Quit LUT cipher mode
```
```c
void EncryptSBox(uint8_t plaintext[16], uint8_t ciphertext[16]);
void DecryptSBox(uint8_t ciphertext[16], uint8_t plaintext[16]);

void EncryptLUT(uint8_t plaintext[16], uint8_t ciphertext[16]);
void DecryptLUT(uint8_t ciphertext[16], uint8_t plaintext[16]);
```

Assign the **key[]** and its proper **size (byte)** to use different key lengths in AES. This library does not perform any input validation. Please ensure that the input data and key sizes are appropriate for the selected AES variant (128, 192, or 256 bits).

| Variant |     Key Length      | Rounds (Nr) |
| :-----: | :-----------------: | :---------: |
| AES-128 | 16 Bytes (128 Bits) |     10      |
| AES-192 | 24 Bytes (192 Bits) |     12      |
| AES-256 | 32 Bytes (256 Bits) |     14      |

Functions for debugging:

```c
void PrintState(uint8_t state[4][4]);
void PrintKeyList(uint8_t **keyarray);
void PrintLUT(uint8_t ***table);
```
### opmode.h

Supports operation modes of block ciphers such as ECB, CBC for binary file I/O. Tested with NIST Special Publication 800-38A example vectors. Other modes will be implemented later on.

```c
void EncryptECB(char *infilename, char *outfilename);
void DecryptECB(char *infilename, char *outfilename);

void SetIV(uint8_t *iv); //Must be called before en/decryptions
void EncryptCBC(char *infilename, char *outfilename);
void DecryptCBC(char *infilename, char *outfilename);

//To be done
void EncryptCFB(char *infilename, char *outfilename);
void DecryptCFB(char *infilename, char *outfilename);
```

S-Box/LUT are also supported when calling these functions above. You can call SetLUTMode() or QuitLUTMode() before en/decryptions.

Padding pattern is implemented with **PKCS#7** standard.

## To-do

- Implement other modes of operation for block ciphers such as CFB, OFB, etc.
- Implement AES-CMAC.