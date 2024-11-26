#include <stdio.h>
#include <stdint.h>
uint8_t permute(uint8_t input, const int *table, int table_size) {
	int i;
    uint8_t output = 0;
    for (i = 0; i < table_size; i++) {
        output |= ((input >> (8 - table[i])) & 1) << (table_size - i - 1);
    }
    return output;
}
uint8_t sdes_encrypt(uint8_t plaintext, uint8_t key) {
    return plaintext ^ key;
}
uint8_t sdes_decrypt(uint8_t ciphertext, uint8_t key) {
    return ciphertext ^ key;
}
void cbc_encrypt(uint8_t *plaintext, uint8_t *ciphertext, int blocks, uint8_t key, uint8_t iv) {
	int i;
    uint8_t previous = iv;
    for (i = 0; i < blocks; i++) {
        uint8_t input = plaintext[i] ^ previous;
        ciphertext[i] = sdes_encrypt(input, key);
        previous = ciphertext[i];
    }
}
void cbc_decrypt(uint8_t *ciphertext, uint8_t *plaintext, int blocks, uint8_t key, uint8_t iv) {
	int i;
    uint8_t previous = iv;
    for (i = 0; i < blocks; i++) {
        uint8_t decrypted = sdes_decrypt(ciphertext[i], key);
        plaintext[i] = decrypted ^ previous;
        previous = ciphertext[i];
    }
}
void print_binary(const char *label, uint8_t *data, int size) {
	int i,j;
    printf("%s: ", label);
    for (i = 0; i < size; i++) {
        for (j = 7; j >= 0; j--) {
            printf("%d", (data[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n");
}
int main() {
    uint8_t plaintext[] = {0x00, 0x01, 0x02, 0x03};
    uint8_t key = 0xFD;
    uint8_t iv = 0xAA;
    int blocks = sizeof(plaintext);
    uint8_t ciphertext[blocks];
    uint8_t decrypted[blocks];
    cbc_encrypt(plaintext, ciphertext, blocks, key, iv);
    print_binary("Ciphertext", ciphertext, blocks);
    cbc_decrypt(ciphertext, decrypted, blocks, key, iv);
    print_binary("Decrypted Plaintext", decrypted, blocks);
    return 0;
}
