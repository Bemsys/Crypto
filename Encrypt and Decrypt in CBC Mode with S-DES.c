#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define BLOCK_SIZE 8
void xor_blocks(uint8_t *block1, uint8_t *block2, uint8_t *result) {
	int i;
    for (i = 0; i < BLOCK_SIZE; i++) {
        result[i] = block1[i] ^ block2[i];
    }
}
void block_cipher(uint8_t *block, uint8_t key, uint8_t *ciphertext) {
	int i;
    for (i = 0; i < BLOCK_SIZE; i++) {
        ciphertext[i] = block[i] ^ key;
    }
}
void cbc_mac(uint8_t *message, uint8_t key, uint8_t *mac) {
    uint8_t block[BLOCK_SIZE];
    memcpy(block, message, BLOCK_SIZE);
    block_cipher(block, key, mac);
}
void cbc_mac_two_block_attack(uint8_t *message, uint8_t *mac, uint8_t key, uint8_t *attack_mac) {
    uint8_t block1[BLOCK_SIZE], block2[BLOCK_SIZE], xor_result[BLOCK_SIZE];
    memcpy(block1, message, BLOCK_SIZE);
    memcpy(block2, message + BLOCK_SIZE, BLOCK_SIZE);
    xor_blocks(block2, mac, xor_result);
    uint8_t intermediate[BLOCK_SIZE];
    block_cipher(block1, key, intermediate);
    block_cipher(xor_result, key, attack_mac);
}
void print_block(const char *label, uint8_t *block) {
	int i;
    printf("%s: ", label);
    for (i = 0; i < BLOCK_SIZE; i++) {
        printf("%02X ", block[i]);
    }
    printf("\n");
}
int main() {
    uint8_t message[BLOCK_SIZE * 2] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t key = 0xAA;
    uint8_t mac[BLOCK_SIZE];
    uint8_t attack_mac[BLOCK_SIZE];
    cbc_mac(message, key, mac);
    print_block("MAC of X", mac);
    cbc_mac_two_block_attack(message, mac, key, attack_mac);
    print_block("MAC for X || (X ? T)", attack_mac);
    return 0;
}
