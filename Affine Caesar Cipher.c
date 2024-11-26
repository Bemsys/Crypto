#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
int modInverse(int a, int m) {
	int x;
    a = a % m;
    for (x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1;
}
void encrypt(const char *plaintext, char *ciphertext, int a, int b) {
	int i;
    for (i = 0; plaintext[i] != '\0'; ++i) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = ((a * (plaintext[i] - base) + b) % 26) + base;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
}
void decrypt(const char *ciphertext, char *plaintext, int a, int b) {
	int i;
    int a_inv = modInverse(a, 26);
    if (a_inv == -1) {
        printf("Decryption impossible: 'a' has no modular inverse mod 26.\n");
        exit(1);
    }
    for (i = 0; ciphertext[i] != '\0'; ++i) {
        if (isalpha(ciphertext[i])) {
            char base = isupper(ciphertext[i]) ? 'A' : 'a';
            plaintext[i] = ((a_inv * ((ciphertext[i] - base) - b + 26)) % 26) + base;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
int main() {
    char plaintext[100], ciphertext[100], decrypted[100];
    int a, b, choice;
    printf("Enter the plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';
    printf("Enter values for 'a' and 'b':\n");
    printf("a (must be coprime with 26): ");
    scanf("%d", &a);
    printf("b (any integer): ");
    scanf("%d", &b);
    if (gcd(a, 26) != 1) {
        printf("Invalid 'a' value. It must be coprime with 26.\n");
        return 1;
    }
    printf("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
    scanf("%d", &choice);
    if (choice == 1) {
        encrypt(plaintext, ciphertext, a, b);
        printf("Encrypted text: %s\n", ciphertext);
    } else if (choice == 2) {
        printf("Enter the ciphertext: ");
        getchar();
        fgets(ciphertext, sizeof(ciphertext), stdin);
        ciphertext[strcspn(ciphertext, "\n")] = '\0';
        decrypt(ciphertext, decrypted, a, b);
        printf("Decrypted text: %s\n", decrypted);
    } else {
        printf("Invalid choice!\n");
    }
    return 0;
}
