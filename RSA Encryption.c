#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define BLOCK_SIZE 8
int pad_plaintext(uint8_t *plaintext, int length) {
	int i;
    int pad_length = BLOCK_SIZE - (length % BLOCK_SIZE);
    for (i = 0; i < pad_length; i++) {
        plaintext[length + i] = (i == 0) ? 0x80 : 0x00;
    }
    return length + pad_length;
}
void ecb_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key) {
	int i,j;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        for (j = 0; j < BLOCK_SIZE; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ key;
        }
    }
}
void ecb_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key) {
	int i,j;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        for (j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ key;
        }
    }
}
void cbc_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key, uint8_t iv) {
	int i,j;
    uint8_t previous = iv;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        for (j = 0; j < BLOCK_SIZE; j++) {
            ciphertext[i + j] = (plaintext[i + j] ^ previous) ^ key;
            previous = ciphertext[i + j];
        }
    }
}
void cbc_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key, uint8_t iv) {
	int i,j;
    uint8_t previous = iv;
    for (i = 0; i < length; i += BLOCK_SIZE) {
        for (j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] = (ciphertext[i + j] ^ key) ^ previous;
            previous = ciphertext[i + j];
        }
    }
}
void cfb_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t feedback = iv;
    for (i = 0; i < length; i++) {
        ciphertext[i] = plaintext[i] ^ (feedback ^ key);
        feedback = ciphertext[i];
    }
}
void cfb_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int length, uint8_t key, uint8_t iv) {
	int i;
    uint8_t feedback = iv;
    for (i = 0; i < length; i++) {
        plaintext[i] = ciphertext[i] ^ (feedback ^ key);
        feedback = ciphertext[i];
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
    uint8_t plaintext[] = "This is a test message.";
    int length = strlen((char *)plaintext);
    uint8_t key = 0x5A;
    uint8_t iv = 0xA5;
    int padded_length = pad_plaintext(plaintext, length);
    uint8_t ciphertext[padded_length];
    uint8_t decrypted[padded_length];
    printf("Original Plaintext:\n");
    print_data("Plaintext", plaintext, padded_length);
    printf("\nECB Mode:\n");
    ecb_encrypt(plaintext, ciphertext, padded_length, key);
    print_data("Ciphertext", ciphertext, padded_length);
    ecb_decrypt(ciphertext, decrypted, padded_length, key);
    print_data("Decrypted", decrypted, padded_length);
    printf("\nCBC Mode:\n");
    cbc_encrypt(plaintext, ciphertext, padded_length, key, iv);
    print_data("Ciphertext", ciphertext, padded_length);
    cbc_decrypt(ciphertext, decrypted, padded_length, key, iv);
    print_data("Decrypted", decrypted, padded_length);
    printf("\nCFB Mode:\n");
    cfb_encrypt(plaintext, ciphertext, padded_length, key, iv);
    print_data("Ciphertext", ciphertext, padded_length);
    cfb_decrypt(ciphertext, decrypted, padded_length, key, iv);
    print_data("Decrypted", decrypted, padded_length);
    return 0;
}
