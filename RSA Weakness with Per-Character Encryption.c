#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#define ALPHABET_SIZE 26
void generate_key_stream(int *key_stream, int length) {
	int i;
    for (i = 0; i < length; i++) {
        key_stream[i] = rand() % ALPHABET_SIZE;
    }
}
void encrypt(char *plaintext, int *key_stream, char *ciphertext, int length) {
	int i;
    for (i = 0; i < length; i++) {
        if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            ciphertext[i] = 'A' + ((plaintext[i] - 'A' + key_stream[i]) % ALPHABET_SIZE);
        } else if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            ciphertext[i] = 'a' + ((plaintext[i] - 'a' + key_stream[i]) % ALPHABET_SIZE);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
}
void decrypt(char *ciphertext, int *key_stream, char *decrypted_text, int length) {
	int i;
    for (i = 0; i < length; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            decrypted_text[i] = 'A' + ((ciphertext[i] - 'A' - key_stream[i] + ALPHABET_SIZE) % ALPHABET_SIZE);
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            decrypted_text[i] = 'a' + ((ciphertext[i] - 'a' - key_stream[i] + ALPHABET_SIZE) % ALPHABET_SIZE);
        } else {
            decrypted_text[i] = ciphertext[i];
        }
    }
}
int main() {
    int i;
    srand(time(NULL));
    char plaintext[] = "Hello World!";
    int length = strlen(plaintext);
    int key_stream[length];
    generate_key_stream(key_stream, length);
    printf("Plaintext: %s\n", plaintext);
    printf("Key Stream: ");
    for (i = 0; i < length; i++) {
        printf("%d ", key_stream[i]);
    }
    printf("\n");
    char ciphertext[length + 1];
    encrypt(plaintext, key_stream, ciphertext, length);
    ciphertext[length] = '\0';
    printf("Encrypted Ciphertext: %s\n", ciphertext);
    char decrypted_text[length + 1];
    decrypt(ciphertext, key_stream, decrypted_text, length);
    decrypted_text[length] = '\0';
    printf("Decrypted Text: %s\n", decrypted_text);
    return 0;
}
