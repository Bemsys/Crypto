#include <stdio.h>
#include <stdint.h>
#define DES_KEY_SIZE 64
#define PC1_SIZE 56
#define PC2_SIZE 48
#define NUM_ROUNDS 16
static const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};
static const int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};
static const int LEFT_SHIFT_SCHEDULE[NUM_ROUNDS] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};
uint64_t permute(uint64_t input, const int *table, int table_size, int input_size) {
	int i;
    uint64_t output = 0;
    for (i = 0; i < table_size; i++) {
        output |= ((input >> (input_size - table[i])) & 1) << (table_size - i - 1);
    }
    return output;
}
uint32_t left_shift(uint32_t half, int shifts) {
    return ((half << shifts) | (half >> (28 - shifts))) & 0x0FFFFFFF;
}
void generate_subkeys(uint64_t initial_key, uint64_t subkeys[NUM_ROUNDS]) {
	int round;
    uint64_t permuted_key = permute(initial_key, PC1, PC1_SIZE, DES_KEY_SIZE);
    uint32_t C = (permuted_key >> 28) & 0x0FFFFFFF;
    uint32_t D = permuted_key & 0x0FFFFFFF;
    for (round = 0; round < NUM_ROUNDS; round++) {
        C = left_shift(C, LEFT_SHIFT_SCHEDULE[round]);
        D = left_shift(D, LEFT_SHIFT_SCHEDULE[round]);
        uint64_t combined = ((uint64_t)C << 28) | D;
        subkeys[round] = permute(combined, PC2, PC2_SIZE, PC1_SIZE);
    }
}
int main() {
	int i;
    uint64_t initial_key = 0x133457799BBCDFF1;\
    uint64_t subkeys[NUM_ROUNDS];
    generate_subkeys(initial_key, subkeys);
    printf("Generated Subkeys:\n");
    for (i = 0; i < NUM_ROUNDS; i++) {
        printf("K%d: %012llX\n", i + 1, subkeys[i]);
    }
    return 0;
}
