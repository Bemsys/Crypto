#include <stdio.h>
#include <ctype.h>
int mod_inverse(int a, int m) {
	int x;
    for (x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;
}
void affine_encrypt(char* plaintext, int a, int b) {
	int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            plaintext[i] = ((a * (plaintext[i] - base) + b) % 26) + base;
        }
    }
}
void affine_decrypt(char* ciphertext, int a, int b) {
	int i;
    int m = 26;
    int a_inv = mod_inverse(a, m);
    if (a_inv == -1) {
        printf("No modular inverse exists for the given key 'a'\n");
        return;
    }

    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            char base = isupper(ciphertext[i]) ? 'A' : 'a';
            ciphertext[i] = (a_inv * (ciphertext[i] - base - b + m) % m) + base;
        }
    }
}
int main() {
    char plaintext[] = "Hello World";
    printf("Original Message: %s\n", plaintext);
    int a = 5;
    int b = 8;
    affine_encrypt(plaintext, a, b);
    printf("Encrypted Message: %s\n", plaintext);
    affine_decrypt(plaintext, a, b);
    printf("Decrypted Message: %s\n", plaintext);
    return 0;
}
