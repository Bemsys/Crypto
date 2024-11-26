#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define DES_KEY_SIZE 56
#define DES_BLOCK_SIZE 64
#define LEFT_SHIFT_SCHEDULE {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1} 
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7, 59, 51, 43, 35, 27, 19, 11, 3,
    56, 48, 40, 32, 24, 16, 8, 0
};
static const int FP[64] = {
    39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};
void permute(uint64_t *block, const int* permutation_table, int table_size) {
	int i;
    uint64_t result = 0;
    for (i = 0; i < table_size; i++) {
        result |= ((*block >> (64 - permutation_table[i])) & 1) << (table_size - i - 1);
    }
    *block = result;
}
void left_shift(uint32_t *block, int shifts) {
    *block = (*block << shifts) | (*block >> (28 - shifts));
    *block &= 0x0FFFFFFF;
}
void generate_subkeys(uint64_t key, uint64_t subkeys[16]) {
	int round;
    static const int PC1[56] = {
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    uint32_t C = 0, D = 0;
    permute(&key, PC1, 56);
    C = (key >> 28) & 0x0FFFFFFF;
    D = key & 0x0FFFFFFF;
    int shifts[16] = LEFT_SHIFT_SCHEDULE;
    for (round = 0; round < 16; round++) {
        left_shift(&C, shifts[round]);
        left_shift(&D, shifts[round]);
        uint64_t combined = ((uint64_t)C << 28) | D;
        static const int PC2[48] = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };
        permute(&combined, PC2, 48);
        subkeys[round] = combined;
    }
}
uint32_t feistel_function(uint32_t half_block, uint64_t subkey) {
	int i;
    static const int E[48] = {
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
        24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };
    uint64_t expanded_half = 0;
    for (i = 0; i < 48; i++) {
        expanded_half |= ((half_block >> (32 - E[i])) & 1) << (47 - i);
    }
    expanded_half ^= subkey;
    static const int S[8][4][16] = {
        {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
         {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
         {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
         {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},\
        {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
         {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
         {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
         {13, 8, 10, 1, 15, 12, 9, 4, 5, 0, 15, 3, 2, 11, 14, 7}},
    };
    uint32_t substituted = 0;
    for (i = 0; i < 8; i++) {
        uint8_t block = (expanded_half >> (6 * i)) & 0x3F;
        int row = ((block >> 5) & 0x2) | (block & 0x1);
        int col = (block >> 1) & 0xF;
        substituted |= S[i][row][col] << (4 * (7 - i));
    }
    static const int P[32] = {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    };
    uint32_t permuted = 0;
    for (i = 0; i < 32; i++) {
        permuted |= ((substituted >> (32 - P[i])) & 1) << (31 - i);
    }
    return permuted;
}
void des_decrypt(uint64_t ciphertext, uint64_t subkeys[16], uint64_t *plaintext) {
	int round;
    uint64_t block = ciphertext;
    permute(&block, IP, 64);
    uint32_t left = block >> 32;
    uint32_t right = block & 0xFFFFFFFF;
    for (round = 15; round >= 0; round--) {
        uint32_t new_right = left ^ feistel_function(right, subkeys[round]);
        left = right;
        right = new_right;
    }
    block = ((uint64_t)right << 32) | left;
    permute(&block, FP, 64);
    *plaintext = block;
}
int main() {
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t ciphertext = 0x0123456789ABCDEF;
    uint64_t subkeys[16];
    generate_subkeys(key, subkeys);
    uint64_t plaintext;
    des_decrypt(ciphertext, subkeys, &plaintext);
    printf("Decrypted plaintext: %llx\n", plaintext);
    return 0;
}
