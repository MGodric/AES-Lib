#ifndef AES_LIB_OPMODE_H
#define AES_LIB_OPMODE_H

#include <string.h>
#include <time.h>
#include "aes.h"

void EncryptECB(char *infilename, char *outfilename);
void DecryptECB(char *infilename, char *outfilename);

void SetIV(uint8_t *iv);
void EncryptCBC(char *infilename, char *outfilename);
void DecryptCBC(char *infilename, char *outfilename);

//To be done
void EncryptCFB(char *infilename, char *outfilename);
void DecryptCFB(char *infilename, char *outfilename);

#endif //AES_LIB_OPMODE_H
