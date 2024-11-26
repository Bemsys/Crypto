#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define BLOCK_SIZE 8
#define MAX_MESSAGE_SIZE 1024
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
void pad_plaintext(uint8_t *plaintext, int *length, int block_size) {
	int i;
    int pad_length = block_size - (*length % block_size);
    for (i = *length; i < *length + pad_length; i++) {
        plaintext[i] = pad_length;
    }
    *length += pad_length;
}
void ecb_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key) {
	int i;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        block_cipher(plaintext + i, key, ciphertext + i);
    }
}
void ecb_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key) {
	int i;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        block_cipher(ciphertext + i, key, plaintext + i);
    }
}
void cbc_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t previous = iv;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t input_block[BLOCK_SIZE];
        xor_blocks(plaintext + i, &previous, input_block);
        block_cipher(input_block, key, ciphertext + i);
        previous = ciphertext[i];
    }
}
void cbc_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t previous = iv;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        uint8_t decrypted_block[BLOCK_SIZE];
        block_cipher(ciphertext + i, key, decrypted_block);
        xor_blocks(decrypted_block, &previous, plaintext + i);
        previous = ciphertext[i];
    }
}
void cfb_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t feedback = iv;
    for (i = 0; i < length; i++) {
        ciphertext[i] = plaintext[i] ^ feedback;
        block_cipher(&feedback, key, &feedback);
    }
}
void cfb_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t feedback = iv;
    for (i = 0; i < length; i++) {
        plaintext[i] = ciphertext[i] ^ feedback;
        block_cipher(&feedback, key, &feedback);
    }
}
void print_data(const char *label, uint8_t *data, int length) {
	int i;
    printf("%s: ", label);
    for (i = 0; i < length; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
int main() {
    uint8_t plaintext[MAX_MESSAGE_SIZE] = "This is a test message.";
    int length = strlen((char *)plaintext);
    uint8_t key = 0xAA;
    uint8_t iv = 0x55;
    uint8_t ciphertext[MAX_MESSAGE_SIZE];
    uint8_t decrypted[MAX_MESSAGE_SIZE];
    pad_plaintext(plaintext, &length, BLOCK_SIZE);
    print_data("Original plaintext", plaintext, length);
    ecb_encrypt(plaintext, ciphertext, length, key);
    print_data("Ciphertext (ECB)", ciphertext, length);
    ecb_decrypt(ciphertext, decrypted, length, key);
    print_data("Decrypted (ECB)", decrypted, length);
    cbc_encrypt(plaintext, ciphertext, length, key, iv);
    print_data("Ciphertext (CBC)", ciphertext, length);
    cbc_decrypt(ciphertext, decrypted, length, key, iv);
    print_data("Decrypted (CBC)", decrypted, length);
    cfb_encrypt(plaintext, ciphertext, length, key, iv);
    print_data("Ciphertext (CFB)", ciphertext, length);
    cfb_decrypt(ciphertext, decrypted, length, key, iv);
    print_data("Decrypted (CFB)", decrypted, length);
    return 0;
}
