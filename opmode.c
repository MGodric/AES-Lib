#include "opmode.h"

static const int BLOCK_SIZE = 16;
static uint8_t *iv;


static void SetFile(char *infilename, char *outfilename, FILE **rfp, FILE **wfp) {
    *rfp = fopen(infilename, "rb");
    if (*rfp == NULL)
        fprintf(stderr, "Error: Cannot open file %s (During function: SetFile).\n", infilename);

    *wfp = fopen(outfilename, "wb");
    if (*wfp == NULL)
        fprintf(stderr, "Error: Cannot open file %s (During function: SetFile).\n", outfilename);
    fseek(*wfp, 0, SEEK_SET);
}

static int GetFileSize(FILE *rfp) {
    fseek(rfp, 0, SEEK_END);
    int size = ftell(rfp);
    fseek(rfp, 0, SEEK_SET);

    return size;
}

static void PKCS7Padding(uint8_t *plaintext, uint8_t tailsize) {
    if (tailsize == 0)
        memset(plaintext, 0x10, BLOCK_SIZE);
    else
        memset(plaintext + tailsize, BLOCK_SIZE - tailsize, BLOCK_SIZE - tailsize);
}

static int8_t PKCS7UnPadding(uint8_t *plainblock) {
    int8_t padsize = plainblock[BLOCK_SIZE - 1];
    for (int i = BLOCK_SIZE - 1; i >= BLOCK_SIZE - padsize; i--) {
        if (plainblock[i] != padsize) {
            fprintf(stderr, "Error: Invalid padding pattern (During function: PKCS7UnPadding).\n");
            return -1;
        }
    }
    return padsize;
}

void EncryptECB(char *infilename, char *outfilename) {
    FILE *rfp = NULL;
    FILE *wfp = NULL;
    SetFile(infilename, outfilename, &rfp, &wfp);

    int filesize = GetFileSize(rfp);
    int repeat = filesize / BLOCK_SIZE;
    uint8_t tailsize = filesize % BLOCK_SIZE;
    uint8_t *plainblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *cipherblock = calloc(BLOCK_SIZE, sizeof(uint8_t));

    if (ciphermode == SBOX) {
        for (int i = 0; i < repeat; i++) {
            fread(plainblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            EncryptSBox(plainblock, cipherblock);
            fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(plainblock, sizeof(uint8_t), tailsize, rfp);
        PKCS7Padding(plainblock, tailsize);
        EncryptSBox(plainblock, cipherblock);
        fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
    } else if (ciphermode == LUT) {
        for (int i = 0; i < repeat; i++) {
            fread(plainblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            EncryptLUT(plainblock, cipherblock);
            fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(plainblock, sizeof(uint8_t), tailsize, rfp);
        PKCS7Padding(plainblock, tailsize);
        EncryptLUT(plainblock, cipherblock);
        fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
    }
    fclose(rfp);
    fclose(wfp);
    printf("Encryption Complete!\n");
    free(plainblock);
    free(cipherblock);
}

void DecryptECB(char *infilename, char *outfilename) {
    FILE *rfp = NULL;
    FILE *wfp = NULL;
    SetFile(infilename, outfilename, &rfp, &wfp);
    int filesize = GetFileSize(rfp);

    if (filesize % BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: File size is not multiple of block size (During function: DecryptECB).\n");
        fclose(rfp);
        fclose(wfp);
        return;
    }
    int repeat = filesize / BLOCK_SIZE;
    uint8_t *cipherblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *plainblock = calloc(BLOCK_SIZE, sizeof(uint8_t));

    if (ciphermode == SBOX) {
        for (int i = 0; i < repeat - 1; i++) {
            fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            DecryptSBox(cipherblock, plainblock);
            fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
        DecryptSBox(cipherblock, plainblock);
        int8_t padsize = PKCS7UnPadding(plainblock);
        if (padsize != -1)
            fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE - padsize, wfp);
        else return;
    } else if (ciphermode == LUT) {
        for (int i = 0; i < repeat - 1; i++) {
            fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            DecryptLUT(cipherblock, plainblock);
            fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
        DecryptLUT(cipherblock, plainblock);
        int8_t padsize = PKCS7UnPadding(plainblock);
        fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE - padsize, wfp);
    }
    fclose(rfp);
    fclose(wfp);
    printf("Decryption Complete!\n");
    free(plainblock);
    free(cipherblock);
}

void SetIV(uint8_t *inputiv) {
    if (iv == NULL) {
        iv = calloc(BLOCK_SIZE, sizeof(uint8_t));
        if (iv == NULL) {
            fprintf(stderr, "Error: Cannot allocate memory (During function: SetIV).\n");
            return;
        }
    }
    if (inputiv == NULL) {
        srand((unsigned int) time(NULL));
        printf("Generated a random IV: ");
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = rand() % 256;
            printf("%02x", iv[i]);
        }
        printf("\n");
    } else
        memcpy(iv, inputiv, BLOCK_SIZE);
}

void EncryptCBC(char *infilename, char *outfilename) {
    if (iv == NULL) {
        fprintf(stderr, "Error: IV unavailable (During function: EncryptCBC).\n");
        return;
    }
    FILE *rfp = NULL;
    FILE *wfp = NULL;
    SetFile(infilename, outfilename, &rfp, &wfp);
    int filesize = GetFileSize(rfp);
    int repeat = filesize / BLOCK_SIZE;
    uint8_t tailsize = filesize % BLOCK_SIZE;
    uint8_t *plainblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *cipherblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *temp = calloc(BLOCK_SIZE, sizeof(uint8_t));

    memcpy(temp, iv, BLOCK_SIZE);
    if (ciphermode == SBOX) {
        for (int i = 0; i < repeat; i++) {
            fread(plainblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            for (int j = 0; j < BLOCK_SIZE; j++)
                plainblock[j] ^= temp[j];
            EncryptSBox(plainblock, cipherblock);
            memcpy(temp, cipherblock, BLOCK_SIZE);
            fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(plainblock, sizeof(uint8_t), tailsize, rfp);
        PKCS7Padding(plainblock, tailsize);
        for (int j = 0; j < BLOCK_SIZE; j++)
            plainblock[j] ^= temp[j];
        EncryptSBox(plainblock, cipherblock);
        fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
    } else if (ciphermode == LUT) {
        for (int i = 0; i < repeat; i++) {
            fread(plainblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            for (int j = 0; j < BLOCK_SIZE; j++)
                plainblock[j] ^= temp[j];
            EncryptLUT(plainblock, cipherblock);
            memcpy(temp, cipherblock, BLOCK_SIZE);
            fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(plainblock, sizeof(uint8_t), tailsize, rfp);
        PKCS7Padding(plainblock, tailsize);
        for (int j = 0; j < BLOCK_SIZE; j++)
            plainblock[j] ^= temp[j];
        EncryptLUT(plainblock, cipherblock);
        fwrite(cipherblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
    }
    fclose(rfp);
    fclose(wfp);
    printf("Encryption Complete! Change of the IV is advised.\n");
    free(plainblock);
    free(cipherblock);
    free(temp);
}

void DecryptCBC(char *infilename, char *outfilename) {
    if (iv == NULL) {
        fprintf(stderr, "Error: IV unavailable (During function: DecryptCBC).\n");
        return;
    }
    FILE *rfp = NULL;
    FILE *wfp = NULL;
    SetFile(infilename, outfilename, &rfp, &wfp);
    int filesize = GetFileSize(rfp);

    if (filesize % BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: File size is not multiple of block size (During function: DecryptECB).\n");
        fclose(rfp);
        fclose(wfp);
        return;
    }
    int repeat = filesize / BLOCK_SIZE;
    uint8_t *cipherblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *plainblock = calloc(BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *temp = calloc(BLOCK_SIZE, sizeof(uint8_t));
    memcpy(temp, iv, BLOCK_SIZE);
    if (ciphermode == SBOX) {
        for (int i = 0; i < repeat - 1; i++) {
            fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            DecryptSBox(cipherblock, plainblock);
            for (int j = 0; j < BLOCK_SIZE; j++)
                plainblock[j] ^= temp[j];
            memcpy(temp, cipherblock, BLOCK_SIZE);
            fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
        DecryptSBox(cipherblock, plainblock);
        for (int i = 0; i < BLOCK_SIZE; i++)
            plainblock[i] ^= temp[i];
        PKCS7UnPadding(plainblock);
        fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
    } else if (ciphermode == LUT) {
        for (int i = 0; i < repeat - 1; i++) {
            fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
            DecryptLUT(cipherblock, plainblock);
            for (int j = 0; j < BLOCK_SIZE; j++)
                plainblock[j] ^= temp[j];
            memcpy(temp, cipherblock, BLOCK_SIZE);
            fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE, wfp);
        }
        fread(cipherblock, sizeof(uint8_t), BLOCK_SIZE, rfp);
        DecryptLUT(cipherblock, plainblock);
        for (int i = 0; i < BLOCK_SIZE; i++)
            plainblock[i] ^= temp[i];
        int8_t padsize = PKCS7UnPadding(plainblock);
        fwrite(plainblock, sizeof(uint8_t), BLOCK_SIZE - padsize, wfp);
    }
    fclose(rfp);
    fclose(wfp);
    printf("Decryption Complete!\n");
    free(plainblock);
    free(cipherblock);
    free(temp);
}

//To be done
void EncryptCFB(char *infilename, char *outfilename) {

}

void DecryptCFB(char *infilename, char *outfilename) {

}
