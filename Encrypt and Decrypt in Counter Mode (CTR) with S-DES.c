#include <stdio.h>
#include <stdint.h>
#include <string.h>
void left_shift(uint64_t *block, int block_size) {
    *block = *block << 1;
    if (block_size == 128 && (*block >> 128)) {
        *block ^= 0x87;
    } else if (block_size == 64 && (*block >> 64)) {
        *block ^= 0xC0;
    }
}
void generate_subkeys(uint64_t *K1, uint64_t *K2, int block_size) {
    uint64_t block = 0;
    left_shift(&block, block_size);
    *K1 = block;
    left_shift(&block, block_size);
    *K2 = block;
}
void print_binary(uint64_t value, int block_size) {
	int i;
    for (i = block_size - 1; i >= 0; i--) {
        printf("%d", (value >> i) & 1);
    }
    printf("\n");
}
int main() {
    uint64_t K1, K2;
    printf("For 128-bit block size:\n");
    generate_subkeys(&K1, &K2, 128);
    printf("K1: ");
    print_binary(K1, 128);
    printf("K2: ");
    print_binary(K2, 128);
    printf("\nFor 64-bit block size:\n");
    generate_subkeys(&K1, &K2, 64);
    printf("K1: ");
    print_binary(K1, 64);
    printf("K2: ");
    print_binary(K2, 64);
    return 0;
}
