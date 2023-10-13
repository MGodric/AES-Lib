#ifndef AES_LIB_AES_H
#define AES_LIB_AES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define LUT 1
#define SBOX 0

static uint8_t ciphermode = SBOX;

void SetKey(uint8_t key[], uint8_t size);
void SetLUTMode(void);
void QuitLUTMode(void);

void EncryptSBox(uint8_t plaintext[16], uint8_t ciphertext[16]);
void DecryptSBox(uint8_t ciphertext[16], uint8_t plaintext[16]);

void EncryptLUT(uint8_t plaintext[16], uint8_t ciphertext[16]);
void DecryptLUT(uint8_t ciphertext[16], uint8_t plaintext[16]);

#endif //AES_LIB_AES_H
