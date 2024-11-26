#include <stdio.h>
#include <string.h>
#include <ctype.h>
void encrypt(char plaintext[], char key[], char ciphertext[]) {
    int i, j = 0, keyLen = strlen(key);
    for (i = 0; plaintext[i] != '\0'; ++i) {
        if (isalpha(plaintext[i])) {
            char shift = toupper(key[j % keyLen]) - 'A';
            if (isupper(plaintext[i])) {
                ciphertext[i] = ((plaintext[i] - 'A' + shift) % 26) + 'A';
            } else {
                ciphertext[i] = ((plaintext[i] - 'a' + shift) % 26) + 'a';
            }
            j++;
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[i] = '\0';
}
void decrypt(char ciphertext[], char key[], char plaintext[]) {
    int i, j = 0, keyLen = strlen(key);

    for (i = 0; ciphertext[i] != '\0'; ++i) {
        if (isalpha(ciphertext[i])) {
            char shift = toupper(key[j % keyLen]) - 'A';
            if (isupper(ciphertext[i])) {
                plaintext[i] = ((ciphertext[i] - 'A' - shift + 26) % 26) + 'A';
            } else {
                plaintext[i] = ((ciphertext[i] - 'a' - shift + 26) % 26) + 'a';
            }
            j++;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[i] = '\0';
}
int main() {
    char plaintext[100], key[100], result[100];
    int i,choice;
    printf("Enter the plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';
    printf("Enter the key (only alphabetic characters): ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    for (i = 0; key[i] != '\0'; ++i) {
        if (!isalpha(key[i])) {
            printf("Invalid key! The key must contain only alphabetic characters.\n");
            return 1;
        }
    }
    printf("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
    scanf("%d", &choice);
    if (choice == 1) {
        encrypt(plaintext, key, result);
        printf("Encrypted text: %s\n", result);
    } else if (choice == 2) {
        decrypt(plaintext, key, result);
        printf("Decrypted text: %s\n", result);
    } else {
        printf("Invalid choice!\n");
        return 1;
    }
    return 0;
}
