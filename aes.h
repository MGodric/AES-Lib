#ifndef AES_LIB_AES_H
#define AES_LIB_AES_H

extern uint8_t sbox[256];
extern uint8_t invsbox[256];

void PrintState(uint8_t state[4][4]);                   //Print the state
void PrintKeyArray(uint8_t keyarray[][4], uint8_t nr);  //Print the key array of round keys
void PrintTable(uint8_t table[4][256][4]);              //Print a lookup table

void EncryptSBox(uint8_t plaintext[16], uint8_t key[], uint8_t ciphertext[16], uint8_t nr);
void DecryptSBox(uint8_t ciphertext[16], uint8_t key[], uint8_t plaintext[16], uint8_t nr);

void EncryptTable(uint8_t plaintext[16], uint8_t key[], uint8_t ciphertext[16], uint8_t nr);
void DecryptTable(uint8_t ciphertext[16], uint8_t key[], uint8_t plaintext[16], uint8_t nr);

#endif //AES_LIB_AES_H
