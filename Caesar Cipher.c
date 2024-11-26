#include <stdio.h>
#include <string.h>
#include <ctype.h>
void encrypt(char text[], int key) {
    int i;
    char ch;
    for (i = 0; text[i] != '\0'; ++i) {
        ch = text[i];
        if (isupper(ch)) {
            text[i] = (ch + key - 'A') % 26 + 'A';
        }
        else if (islower(ch)) {
            text[i] = (ch + key - 'a') % 26 + 'a';
        }
    }
}
void decrypt(char text[], int key) {
    int i;
    char ch;
    for (i = 0; text[i] != '\0'; ++i) {
        ch = text[i];
        if (isupper(ch)) {
            text[i] = (ch - key - 'A' + 26) % 26 + 'A';
        }
        else if (islower(ch)) {
            text[i] = (ch - key - 'a' + 26) % 26 + 'a';
        }
    }
}
int main() {
    char text[100];
    int key, choice;
    printf("Enter a string to encrypt/decrypt: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';
    printf("Enter the key (1-25): ");
    scanf("%d", &key);
    if (key < 1 || key > 25) {
        printf("Invalid key! Please enter a key between 1 and 25.\n");
        return 1;
    }
    printf("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
    scanf("%d", &choice);
    if (choice == 1) {
        encrypt(text, key);
        printf("Encrypted text: %s\n", text);
    } else if (choice == 2) {
        decrypt(text, key);
        printf("Decrypted text: %s\n", text);
    } else {
        printf("Invalid choice!\n");
        return 1;
    }
    return 0;
}
