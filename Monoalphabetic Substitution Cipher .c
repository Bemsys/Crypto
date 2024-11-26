#include <stdio.h>
#include <string.h>
#include <ctype.h>
void encrypt(char text[], char key[]) {
    int i;
    for (i = 0; text[i] != '\0'; ++i) {
        if (isupper(text[i])) {
            text[i] = key[text[i] - 'A'];
        } else if (islower(text[i])) {
            text[i] = tolower(key[text[i] - 'a']);
        }
    }
}
void decrypt(char text[], char key[]) {
    int i, j;
    char reverseKey[26];
    for (i = 0; i < 26; ++i) {
        reverseKey[key[i] - 'A'] = 'A' + i;
    }
    for (i = 0; text[i] != '\0'; ++i) {
        if (isupper(text[i])) {
            text[i] = reverseKey[text[i] - 'A'];
        } else if (islower(text[i])) {
            text[i] = tolower(reverseKey[text[i] - 'a']);
        }
    }
}
int main() {
    char plaintext[100];
    char key[27];
    int i,j,choice;
    printf("Enter the substitution cipher key (26 unique uppercase letters): ");
    scanf("%s", key);
    if (strlen(key) != 26) {
        printf("Invalid key! The key must contain exactly 26 unique letters.\n");
        return 1;
    }
    for (i = 0; i < 26; ++i) {
        if (!isupper(key[i])) {
            printf("Invalid key! The key must contain only uppercase letters.\n");
            return 1;
        }
        for (j = i + 1; j < 26; ++j) {
            if (key[i] == key[j]) {
                printf("Invalid key! The key must contain unique letters.\n");
                return 1;
            }
        }
    }
    getchar();
    printf("Enter the text to encrypt/decrypt: ");
    fgets(plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn(plaintext, "\n")] = '\0';
    printf("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
    scanf("%d", &choice);
    if (choice == 1) {
        encrypt(plaintext, key);
        printf("Encrypted text: %s\n", plaintext);
    } else if (choice == 2) {
        decrypt(plaintext, key);
        printf("Decrypted text: %s\n", plaintext);
    } else {
        printf("Invalid choice!\n");
        return 1;
    }
    return 0;
}
