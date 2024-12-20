#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define ALPHABET_SIZE 26
void generateCipherAlphabet(const char *keyword, char *cipher) {
	int i;
	char ch;
    int used[ALPHABET_SIZE] = {0};
    int idx = 0;
    for (i = 0; keyword[i] != '\0'; i++) {
        char ch = toupper(keyword[i]);
        if (!used[ch - 'A']) {
            cipher[idx++] = ch;
            used[ch - 'A'] = 1;
        }
    }
    for (ch = 'A'; ch <= 'Z'; ch++) {
        if (!used[ch - 'A']) {
            cipher[idx++] = ch;
        }
    }
    cipher[idx] = '\0';
}
void encrypt(const char *plaintext, const char *cipher, char *ciphertext) {
	int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha(plaintext[i])) {
            int index = toupper(plaintext[i]) - 'A';
            ciphertext[i] = isupper(plaintext[i]) ? cipher[index] : tolower(cipher[index]);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}
void decrypt(const char *ciphertext, const char *cipher, char *plaintext) {
	int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            char upper = toupper(ciphertext[i]);
            int index = strchr(cipher, upper) - cipher;
            plaintext[i] = isupper(ciphertext[i]) ? 'A' + index : 'a' + index;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
int main() {
    const char keyword[] = "CIPHER";
    char cipher[ALPHABET_SIZE + 1];
    generateCipherAlphabet(keyword, cipher);
    printf("Plain alphabet:  abcdefghijklmnopqrstuvwxyz\n");
    printf("Cipher alphabet: %s\n", cipher);
    const char plaintext[] = "This is an example of monoalphabetic cipher.";
    char ciphertext[1024];
    char decrypted[1024];
    encrypt(plaintext, cipher, ciphertext);
    printf("\nPlaintext:  %s\n", plaintext);
    printf("Ciphertext: %s\n", ciphertext);
    decrypt(ciphertext, cipher, decrypted);
    printf("Decrypted:  %s\n", decrypted);
    return 0;
}
