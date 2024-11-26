#include <stdio.h>
#include <stdint.h>
#include <string.h>
uint64_t example_sbox(uint64_t input) {
    return (input ^ 0x3A5C1F29D4E678FB);
}
uint64_t des_encrypt(uint64_t block, uint64_t key) {
    return example_sbox(block ^ key);
}
uint64_t triple_des_encrypt(uint64_t block, uint64_t key1, uint64_t key2, uint64_t key3) {
    uint64_t stage1 = des_encrypt(block, key1);
    uint64_t stage2 = des_encrypt(stage1, key2);
    return des_encrypt(stage2, key3);
}
void cbc_encrypt(uint64_t plaintext[], uint64_t ciphertext[], int blocks, uint64_t iv,
                 uint64_t key1, uint64_t key2, uint64_t key3) {
                 	int i;
    uint64_t previous = iv;
    for (i = 0; i < blocks; i++) {
        uint64_t input_block = plaintext[i] ^ previous;
        ciphertext[i] = triple_des_encrypt(input_block, key1, key2, key3);
        previous = ciphertext[i];
    }
}
void print_block(const char *label, uint64_t block[], int size) {
	int i;
    printf("%s: ", label);
    for (i = 0; i < size; i++) {
        printf("%016llX ", block[i]);
    }
    printf("\n");
}
int main() {
    uint64_t plaintext[] = {0x0123456789ABCDEF, 0x23456789ABCDEF01, 0x3456789ABCDEF012};
    int blocks = sizeof(plaintext) / sizeof(uint64_t);
    uint64_t key1 = 0x133457799BBCDFF1;
    uint64_t key2 = 0x1F1F1F1F0E0E0E0E;
    uint64_t key3 = 0x0A0B0C0D0E0F1011;
    uint64_t iv = 0xAABBCCDDEEFF0011;
    uint64_t ciphertext[blocks];
    cbc_encrypt(plaintext, ciphertext, blocks, iv, key1, key2, key3);
    print_block("Plaintext", plaintext, blocks);
    print_block("Ciphertext", ciphertext, blocks);
    return 0;
}
