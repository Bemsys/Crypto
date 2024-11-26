#include <stdio.h>
#include <string.h>
#define MOD 26
void encrypt(const char plaintext[], const int key[], char ciphertext[]) {
	int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            ciphertext[i] = ((plaintext[i] - 'a' + key[i]) % MOD) + 'a';
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            ciphertext[i] = ((plaintext[i] - 'A' + key[i]) % MOD) + 'A';
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}
void decrypt(const char ciphertext[], const int key[], char plaintext[]) {
	int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = ((ciphertext[i] - 'a' - key[i] + MOD) % MOD) + 'a';
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = ((ciphertext[i] - 'A' - key[i] + MOD) % MOD) + 'A';
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
void compute_key(const char ciphertext[], const char target_plaintext[], int key[]) {
	int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z' && target_plaintext[i] >= 'a' && target_plaintext[i] <= 'z') {
            key[i] = (ciphertext[i] - target_plaintext[i] + MOD) % MOD;
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z' && target_plaintext[i] >= 'A' && target_plaintext[i] <= 'Z') {
            key[i] = (ciphertext[i] - target_plaintext[i] + MOD) % MOD;
        } else {
            key[i] = 0;
        }
    }
}
int main() {
	int i;
    char plaintext[] = "send more money";
    int key[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    char ciphertext[100], decryptedtext[100];
    encrypt(plaintext, key, ciphertext);
    printf("Ciphertext (Part a): %s\n", ciphertext);
    decrypt(ciphertext, key, decryptedtext);
    printf("Decrypted text (verify Part a): %s\n", decryptedtext);
    char target_plaintext[] = "cash not needed";
    int new_key[100];
    compute_key(ciphertext, target_plaintext, new_key);
    printf("New key (Part b): ");
    for (i = 0; i < strlen(target_plaintext); i++) {
        printf("%d ", new_key[i]);
    }
    printf("\n");
    decrypt(ciphertext, new_key, decryptedtext);
    printf("Decrypted text with new key (Part b): %s\n", decryptedtext);
    return 0;
}
