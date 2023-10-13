#include "aes.h"


static const uint8_t sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
static const uint8_t invsbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static uint8_t nr = 0;
static uint8_t **roundkeylist = NULL;
static uint8_t **lut_decry_roundkeylist = NULL;

static uint8_t ***te = NULL;
static uint8_t ***td = NULL;

void PrintKeyList(uint8_t **keyarray) {     //For debugging
    uint8_t line = nr * 4 + 4;
    for (int i = 0; i < line; i++) {
        printf("%02x %02x %02x %02x\n", keyarray[i][0], keyarray[i][1], keyarray[i][2], keyarray[i][3]);
        if ((i + 1) % 4 == 0) printf("\n");
    }
}

void PrintState(uint8_t state[4][4]) {      //For debugging
    for (int i = 0; i < 4; i++)
        printf("%02x %02x %02x %02x\n", state[i][0], state[i][1], state[i][2], state[i][3]);
    printf(("\n"));
}

void PrintLUT(uint8_t ***table) {        //For debugging (Print Tex or Tdx)
    for (int i = 0; i < 4; i++) {
        printf("T%d is:\n", i);
        for (int j = 0; j < 256; j++) {
            printf("%02x%02x%02x%02x\n", table[i][j][0], table[i][j][1], table[i][j][2], table[i][j][3]);
        }
        printf("\n");
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

static void KeyExpansion(void) {
    uint8_t rcon[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    uint8_t temp[4];
    uint8_t nk = nr - 6, num_words = (nr + 1) * 4;

    for (uint8_t i = nk; i < num_words; i++) {  //Generate round key for round 1 ~ nr
        for (uint8_t j = 0; j < 4; j++)
            temp[j] = roundkeylist[i - 1][j];
        if (i % nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= rcon[(i / nk) - 1];
        } else if ((nk > 6) && (i % nk == 4))
            SubWord(temp);
        for (uint8_t j = 0; j < 4; j++)
            roundkeylist[i][j] = roundkeylist[i - nk][j] ^ temp[j];
    }
}

static uint8_t GF28ConstMul(uint8_t a, uint8_t times) {
    uint8_t result = 0;
    uint8_t xtimes_a[4];

    xtimes_a[0] = a;
    for (int i = 1; i < 4; i++) {               //xtimes_a[4] is {a, 2a, 4a, 8a}
        xtimes_a[i] = xtimes_a[i - 1] << 1;     //Process of a * 0x02
        if (xtimes_a[i - 1] & 0x80)
            xtimes_a[i] ^= 0x1b;
    }
    for (int i = 0; i < 4; i++) {               //Process of (a * times)
        if ((times >> i) & 0x01)
            result ^= xtimes_a[i];
    }

    return result;
}

static void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = GF28ConstMul(state[j][i], 0x0e)
                      ^ GF28ConstMul(state[(j + 1) % 4][i], 0x0b)
                      ^ GF28ConstMul(state[(j + 2) % 4][i], 0x0d)
                      ^ GF28ConstMul(state[(j + 3) % 4][i], 0x09);
        }
        for (int j = 0; j < 4; j++)
            state[j][i] = temp[j];
    }
}

static void InvMixColKeyArray(void) {     //InvMixColumns on round keys for round 1 ~ (nr-1)
    uint8_t temp[4][4];

    for (int r = 1; r < nr; r++) {
        for (int i = 0; i < 4; i++) {       //Copy round key of round 1 ~ (nr-1) to temp[4][4]
            for (int j = 0; j < 4; j++)
                temp[j][i] = roundkeylist[4 * r + i][j];
        }
        InvMixColumns(temp);
        for (int i = 0; i < 4; i++) {       //Copy round key back to key array
            for (int j = 0; j < 4; j++)
                lut_decry_roundkeylist[4 * r + i][j] = temp[j][i];
        }
    }
}

void SetKey(uint8_t key[], uint8_t size) {
    static uint8_t numofwords = 0;
    static uint8_t formersize = 0;

    if (size != 16 && size != 24 && size != 32) {
        fprintf(stderr, "Error: Invalid key size (During function: SetKey).\n");
        return;
    }
    if (size != formersize && roundkeylist != NULL) {
        for (int i = 0; i < numofwords; i++) {
            if (roundkeylist[i] != NULL)
                free(roundkeylist[i]);
        }
        free(roundkeylist);
        roundkeylist = NULL;
    }
    if (!(size == formersize && roundkeylist != NULL)) {
        numofwords = 2 * size + 12;
        roundkeylist = (uint8_t **) calloc(numofwords, sizeof(uint8_t *));
        if (roundkeylist == NULL) {
            fprintf(stderr, "Error: Round Key list D1 allocation failed (During function: SetKey).\n");
            return;
        }
        for (int i = 0; i < numofwords; i++) {
            roundkeylist[i] = (uint8_t *) calloc(4, sizeof(uint8_t));
            if (roundkeylist[i] == NULL) {
                fprintf(stderr, "Error, Round Key list D2 allocation failed (During function: SetKey).\n");
                free(roundkeylist);
                return;
            }
        }
    }
    for (uint8_t i = 0; i < size / 4; i++) {
        for (uint8_t j = 0; j < 4; j++)
            roundkeylist[i][j] = key[4 * i + j];
    }
    nr = size / 4 + 6;
    KeyExpansion();

    if (ciphermode == LUT) {
        if (size != formersize && lut_decry_roundkeylist != NULL) {
            for (int i = 0; i < (2 * formersize + 12); i++) {
                if (lut_decry_roundkeylist[i] != NULL)
                    free(lut_decry_roundkeylist[i]);
            }
            free(lut_decry_roundkeylist);
            lut_decry_roundkeylist = NULL;
        }
        if (!(size == formersize && lut_decry_roundkeylist != NULL)) {
            lut_decry_roundkeylist = (uint8_t **) calloc(numofwords, sizeof(uint8_t *));
            if (lut_decry_roundkeylist == NULL) {
                fprintf(stderr, "Error: Round Key list D1 allocation failed (During function: SetKey).\n");
                return;
            }
            for (int i = 0; i < numofwords; i++) {
                lut_decry_roundkeylist[i] = (uint8_t *) calloc(4, sizeof(uint8_t));
                if (lut_decry_roundkeylist[i] == NULL) {
                    fprintf(stderr, "Error, Round Key list D2 allocation failed (During function: SetKey).\n");
                    free(lut_decry_roundkeylist);
                    return;
                }
            }
        }
        for (int i = 0; i < numofwords; i++) {
            for (int j = 0; j < 4; j++) {
                lut_decry_roundkeylist[i][j] = roundkeylist[i][j];
            }
        }
        InvMixColKeyArray();
    }
    formersize = size;
}

void LoadText(uint8_t state[4][4], uint8_t plaintext[]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            state[j][i] = plaintext[4 * i + j];
    }
}

static void AddRoundKey(uint8_t state[4][4], uint8_t **keyarray, uint8_t round) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            state[j][i] ^= keyarray[round * 4 + i][j];
    }
}

static void SubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            state[i][j] = sbox[state[i][j]];
    }
}

static void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            temp[j] = state[i][(i + j) % 4];
        for (int j = 0; j < 4; j++)
            state[i][j] = temp[j];
    }
}

static void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = GF28ConstMul(state[j][i], 0x02)
                      ^ GF28ConstMul(state[(j + 1) % 4][i], 0x03)
                      ^ state[(j + 2) % 4][i]
                      ^ state[(j + 3) % 4][i];
        }
        for (int j = 0; j < 4; j++)
            state[j][i] = temp[j];
    }
}

void EncryptSBox(uint8_t plaintext[16], uint8_t ciphertext[16]) {
    uint8_t state[4][4];

    if (roundkeylist == NULL) {
        fprintf(stderr, "Error: Key unavailable (During function: EncryptSBox).\n");
        return;
    } else if (ciphermode == LUT) {
        fprintf(stderr, "Error: Not in S-Box mode (During function: EncryptSBox).\n)");
        return;
    }

    LoadText(state, plaintext);
    AddRoundKey(state, roundkeylist, 0);
    for (int i = 1; i < nr; i++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundkeylist, i);
        //PrintState(state);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundkeylist, nr);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++)
            ciphertext[r + 4 * c] = state[r][c];
    }
}

static void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp[4];

    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            temp[j] = state[i][(j + 4 - i) % 4];
        for (int j = 0; j < 4; j++)
            state[i][j] = temp[j];
    }
}

static void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            state[i][j] = invsbox[state[i][j]];
    }
}


void DecryptSBox(uint8_t ciphertext[16], uint8_t plaintext[16]) {
    uint8_t state[4][4];

    if (roundkeylist == NULL) {
        fprintf(stderr, "Error: Key unavailable (During function: DecryptSBox).\n");
        return;
    } else if (ciphermode == LUT) {
        fprintf(stderr, "Error: Not in S-Box mode (During function: EncryptSBox).\n)");
        return;
    }

    LoadText(state, ciphertext);
    AddRoundKey(state, roundkeylist, nr);
    for (int i = nr - 1; i > 0; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundkeylist, i);
        InvMixColumns(state);
        //PrintState(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundkeylist, 0);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++)
            plaintext[r + 4 * c] = state[r][c];
    }
}

void TableGen(uint8_t ***table, uint8_t mode) {      //mode 0 for Tex; mode 1 for Tdx
    if (mode == 0) {
        for (int i = 0; i < 256; i++) {     //Generate Te0, with coefficients of (2, 1, 1, 3)
            table[0][i][0] = GF28ConstMul(sbox[i], 0x02);
            table[0][i][1] = sbox[i];
            table[0][i][2] = sbox[i];
            table[0][i][3] = GF28ConstMul(sbox[i], 0x03);
        }
    } else if (mode == 1) {
        for (int i = 0; i < 256; i++) {     //Generate Td0, with coefficients of (e, 9, d, b)
            table[0][i][0] = GF28ConstMul(invsbox[i], 0x0e);
            table[0][i][1] = GF28ConstMul(invsbox[i], 0x09);
            table[0][i][2] = GF28ConstMul(invsbox[i], 0x0d);
            table[0][i][3] = GF28ConstMul(invsbox[i], 0x0b);
        }
    }
    for (int i = 1; i < 4; i++) {       //Generate T1 ~ T3 from T0
        for (int j = 0; j < 256; j++) {
            for (int k = 0; k < 4; k++)
                table[i][j][k] = table[i - 1][j][(k + 3) % 4];  //Example: Te0:2113 -> Te1:1132 -> Te2:1321 -> Te3:3211
        }
    }
}

void SetLUTMode(void) {
    uint8_t numofwords = 8 * nr - 36;

    te = (uint8_t ***) calloc(4, sizeof(uint8_t **));
    if (te == NULL) {
        fprintf(stderr, "Error: Te D1 allocation failed (During function: SetLUTMode).\n");
        return;
    } else
        for (int i = 0; i < 4; i++) {
            te[i] = (uint8_t **) calloc(256, sizeof(uint8_t *));
            if (te[i] == NULL) {
                fprintf(stderr, "Error: Te allocation D2 failed (During function: SetLUTMode).\n");
                return;
            } else
                for (int j = 0; j < 256; j++) {
                    te[i][j] = (uint8_t *) calloc(4, sizeof(uint8_t));
                    if (te[i][j] == NULL) {
                        fprintf(stderr, "Error: Te D3 allocation D3 failed (During function: SetLUTMode).\n");
                        return;
                    }
                }
        }
    td = (uint8_t ***) calloc(4, sizeof(uint8_t **));
    if (td == NULL) {
        fprintf(stderr, "Error: Td D1 allocation failed (During function: SetLUTMode).\n");
        return;
    } else
        for (int i = 0; i < 4; i++) {
            td[i] = (uint8_t **) calloc(256, sizeof(uint8_t *));
            if (td[i] == NULL) {
                fprintf(stderr, "Error: Td allocation D2 failed (During function: SetLUTMode).\n");
                return;
            } else
                for (int j = 0; j < 256; j++) {
                    td[i][j] = (uint8_t *) calloc(4, sizeof(uint8_t));
                    if (td[i][j] == NULL) {
                        fprintf(stderr, "Error: Td D3 allocation D3 failed (During function: SetLUTMode).\n");
                        return;
                    }
                }
        }
    TableGen(te, 0);
    TableGen(td, 1);
    if (lut_decry_roundkeylist == NULL) {
        lut_decry_roundkeylist = (uint8_t **) calloc(numofwords, sizeof(uint8_t *));
        if (lut_decry_roundkeylist == NULL) {
            fprintf(stderr, "Error: Round Key list D1 allocation failed (During function: SetKey).\n");
            return;
        }
        for (int i = 0; i < numofwords; i++) {
            lut_decry_roundkeylist[i] = (uint8_t *) calloc(4, sizeof(uint8_t));
            if (lut_decry_roundkeylist[i] == NULL) {
                fprintf(stderr, "Error: Round Key list D2 allocation failed (During function: SetKey).\n");
                free(lut_decry_roundkeylist);
                return;
            }
        }
    }
    for (int i = 0; i < numofwords; i++) {
        for (int j = 0; j < 4; j++) {
            lut_decry_roundkeylist[i][j] = roundkeylist[i][j];
        }
    }
    InvMixColKeyArray();
    ciphermode = LUT;
    printf("LUT mode set!\n");
}

void QuitLUTMode(void) {
    uint8_t numofwords = 8 * nr - 36;

    if (te != NULL) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                if (te[i][j] != NULL)
                    free(te[i][j]);
            }
            free(te[i]);
        }
        free(te);
        te = NULL;
    } else if (td != NULL) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                if (td[i][j] != NULL)
                    free(td[i][j]);
            }
            free(td[i]);
        }
        free(td);
        te = NULL;
    }
    if (lut_decry_roundkeylist != NULL) {
        for (int i = 0; i < numofwords; i++)
            free(lut_decry_roundkeylist[i]);
        free(lut_decry_roundkeylist);
        lut_decry_roundkeylist = NULL;
    }
    ciphermode = SBOX;
    printf("S-Box mode set!\n");
}


static void TableLookUp(uint8_t state[4][4], uint8_t ***table, uint8_t mode) {  //mode 0 for encrypt; mode 1 for decrypt
    uint8_t temp[4][4];

    if (mode == 0) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++)
                temp[r][c] = table[0][state[0][c]][r]
                             ^ table[1][state[1][(c + 1) % 4]][r]
                             ^ table[2][state[2][(c + 2) % 4]][r]
                             ^ table[3][state[3][(c + 3) % 4]][r];
        }
    } else if (mode == 1) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++)
                temp[r][c] = table[0][state[0][c]][r]
                             ^ table[1][state[1][(c + 3) % 4]][r]
                             ^ table[2][state[2][(c + 2) % 4]][r]
                             ^ table[3][state[3][(c + 1) % 4]][r];
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            state[i][j] = temp[i][j];
    }
}

void EncryptLUT(uint8_t plaintext[16], uint8_t ciphertext[16]) {
    uint8_t state[4][4];

    if (roundkeylist == NULL) {
        fprintf(stderr, "Error: Key unavailable (During function: EncryptSBox).\n");
        return;
    } else if (ciphermode == SBOX) {
        fprintf(stderr, "Error: Not in LUT mode (During function: EncryptLUT).\n");
        return;
    }

    LoadText(state, plaintext);
    AddRoundKey(state, roundkeylist, 0);
    for (int i = 1; i < nr; i++) {
        TableLookUp(state, te, 0);
        AddRoundKey(state, roundkeylist, i);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundkeylist, nr);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++)
            ciphertext[r + 4 * c] = state[r][c];
    }
}


void DecryptLUT(uint8_t ciphertext[16], uint8_t plaintext[16]) {
    uint8_t state[4][4];

    if (lut_decry_roundkeylist == NULL) {
        fprintf(stderr, "Error: Decry-Key unavailable (During function: DecryptLUT).\n");
        return;
    } else if (ciphermode == SBOX) {
        fprintf(stderr, "Error: Not in LUT mode (During function: DecryptLUT).\n");
        return;
    }

    LoadText(state, ciphertext);
    AddRoundKey(state, lut_decry_roundkeylist, nr);
    for (int i = nr - 1; i > 0; i--) {
        TableLookUp(state, td, 1);
        AddRoundKey(state, lut_decry_roundkeylist, i);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, lut_decry_roundkeylist, 0);

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++)
            plaintext[r + 4 * c] = state[r][c];
    }
}