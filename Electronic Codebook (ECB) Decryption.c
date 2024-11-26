#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define BLOCK_SIZE 64
uint64_t encrypt_block(uint64_t plaintext, uint64_t key) {
    return plaintext ^ key;
}
uint64_t decrypt_block(uint64_t ciphertext, uint64_t key) {
    return ciphertext ^ key;
}
void ecb_encrypt(uint64_t plaintext[], uint64_t ciphertext[], int blocks, uint64_t key) {
	int i;
    for (i = 0; i < blocks; i++) {
        ciphertext[i] = encrypt_block(plaintext[i], key);
    }
}
void ecb_decrypt(uint64_t ciphertext[], uint64_t plaintext[], int blocks, uint64_t key) {
	int i;
    for (i = 0; i < blocks; i++) {
        plaintext[i] = decrypt_block(ciphertext[i], key);
    }
}
void cbc_encrypt(uint64_t plaintext[], uint64_t ciphertext[], int blocks, uint64_t key, uint64_t iv) {
	int i;
    uint64_t previous = iv;
    for (i = 0; i < blocks; i++) {
        uint64_t input_block = plaintext[i] ^ previous;
        ciphertext[i] = encrypt_block(input_block, key);
        previous = ciphertext[i];
    }
}
void cbc_decrypt(uint64_t ciphertext[], uint64_t plaintext[], int blocks, uint64_t key, uint64_t iv) {
	int i;
    uint64_t previous = iv;
    for (i = 0; i < blocks; i++) {
        uint64_t decrypted_block = decrypt_block(ciphertext[i], key);
        plaintext[i] = decrypted_block ^ previous;
        previous = ciphertext[i];
    }
}
void print_blocks(const char *label, uint64_t blocks[], int size) {
	int i;
    printf("%s: ", label);
    for (i = 0; i < size; i++) {
        printf("%016llX ", blocks[i]);
    }
    printf("\n");
}
int main() {
    uint64_t plaintext[] = {0x0123456789ABCDEF, 0x23456789ABCDEF01, 0x3456789ABCDEF012};
    int blocks = sizeof(plaintext) / sizeof(uint64_t);
    uint64_t key = 0x133457799BBCDFF1;
    uint64_t iv = 0xAABBCCDDEEFF0011;
    uint64_t ciphertext[blocks];
    uint64_t decrypted[blocks];
    printf("\nECB Mode:\n");
    ecb_encrypt(plaintext, ciphertext, blocks, key);
    print_blocks("Ciphertext", ciphertext, blocks);
    ciphertext[0] ^= 0x0000000000000001;
    print_blocks("Corrupted Ciphertext", ciphertext, blocks);
    ecb_decrypt(ciphertext, decrypted, blocks, key);
    print_blocks("Decrypted Plaintext", decrypted, blocks);
    printf("\nCBC Mode:\n");
    cbc_encrypt(plaintext, ciphertext, blocks, key, iv);
    print_blocks("Ciphertext", ciphertext, blocks);
    ciphertext[0] ^= 0x0000000000000001;
    print_blocks("Corrupted Ciphertext", ciphertext, blocks);
    cbc_decrypt(ciphertext, decrypted, blocks, key, iv);
    print_blocks("Decrypted Plaintext", decrypted, blocks);
    return 0;
}
