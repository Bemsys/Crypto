#include <stdio.h>
#include <stdint.h>
#define BLOCK_SIZE 8
uint8_t sdes_encrypt(uint8_t block, uint8_t key) {
    return block ^ key;
}
void ctr_mode(uint8_t *plaintext, uint8_t *ciphertext, int length, uint8_t key, uint8_t counter) {
	int i;
    for (i = 0; i < length; i++) {
        uint8_t keystream = sdes_encrypt(counter, key);
        ciphertext[i] = plaintext[i] ^ keystream;
        counter++;
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
    uint8_t plaintext[] = {0x00, 0x01, 0x02, 0x04};
    uint8_t key = 0xFD;
    uint8_t counter = 0x00;
    int length = sizeof(plaintext);
    uint8_t ciphertext[length];
    uint8_t decrypted[length];
    ctr_mode(plaintext, ciphertext, length, key, counter);
    print_binary("Ciphertext", ciphertext, length);
    counter = 0x00;
    ctr_mode(ciphertext, decrypted, length, key, counter);\
    print_binary("Decrypted Plaintext", decrypted, length);
    return 0;
}
