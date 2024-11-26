#include <stdio.h>
#include <stdint.h>
#define ALPHABET_SIZE 26
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}
void precompute_ciphertexts(uint64_t ciphertexts[], uint64_t e, uint64_t n) {
	uint64_t m;
    for (m = 0; m < ALPHABET_SIZE; m++) {
        ciphertexts[m] = mod_exp(m, e, n);
    }
}
void decrypt_message(uint64_t *encrypted_message, char *decrypted_message, int length,
                     uint64_t ciphertexts[]) {
                     	int i;
                     	uint64_t m;
    for (i = 0; i < length; i++) {
        for ( m = 0; m < ALPHABET_SIZE; m++) {
            if (encrypted_message[i] == ciphertexts[m]) {
                decrypted_message[i] = 'A' + m;
                break;
            }
        }
    }
    decrypted_message[length] = '\0';
}
int main() {
    uint64_t e = 17;
    uint64_t n = 3233;
    uint64_t encrypted_message[] = {2790, 2201, 2201, 587, 3072};
    int length = sizeof(encrypted_message) / sizeof(encrypted_message[0]);
    uint64_t ciphertexts[ALPHABET_SIZE];
    precompute_ciphertexts(ciphertexts, e, n);
    char decrypted_message[length + 1];
    decrypt_message(encrypted_message, decrypted_message, length, ciphertexts);
    printf("Decrypted Message: %s\n", decrypted_message);
    return 0;
}
