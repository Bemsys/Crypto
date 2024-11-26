#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define SIZE 5
char matrix[SIZE][SIZE];
int positions[26];
void createMatrix(const char *key) {
    int i, j, k = 0, used[26] = {0};
    char letter;
    memset(positions, -1, sizeof(positions));
    for (i = 0; i < strlen(key); ++i) {
        letter = toupper(key[i]);
        if (letter == 'J') letter = 'I';
        if (!used[letter - 'A']) {
            matrix[k / SIZE][k % SIZE] = letter;
            positions[letter - 'A'] = k++;
            used[letter - 'A'] = 1;
        }
    }
    for (letter = 'A'; letter <= 'Z'; ++letter) {
        if (letter == 'J') continue;
        if (!used[letter - 'A']) {
            matrix[k / SIZE][k % SIZE] = letter;
            positions[letter - 'A'] = k++;
            used[letter - 'A'] = 1;
        }
    }
}
void getPosition(char ch, int *row, int *col) {
    int pos = positions[ch - 'A'];
    *row = pos / SIZE;
    *col = pos % SIZE;
}
void processPair(char *ch1, char *ch2, int encrypt) {
    int r1, c1, r2, c2;
    getPosition(*ch1, &r1, &c1);
    getPosition(*ch2, &r2, &c2);
    if (r1 == r2) {
        c1 = (c1 + (encrypt ? 1 : SIZE - 1)) % SIZE;
        c2 = (c2 + (encrypt ? 1 : SIZE - 1)) % SIZE;
    } else if (c1 == c2) {
        r1 = (r1 + (encrypt ? 1 : SIZE - 1)) % SIZE;
        r2 = (r2 + (encrypt ? 1 : SIZE - 1)) % SIZE;
    } else {
        int temp = c1;
        c1 = c2;
        c2 = temp;
    }
    *ch1 = matrix[r1][c1];
    *ch2 = matrix[r2][c2];
}
void preprocessText(char *text) {
    int i, j = 0;
    char processed[100];
    for (i = 0; text[i] != '\0'; ++i) {
        if (isalpha(text[i])) {
            processed[j++] = toupper(text[i] == 'J' ? 'I' : text[i]);
        }
    }
    processed[j] = '\0';
    for (i = 0, j = 0; processed[i] != '\0'; i += 2) {
        if (processed[i] == processed[i + 1]) {
            memmove(&processed[i + 2], &processed[i + 1], strlen(&processed[i + 1]) + 1);
            processed[i + 1] = 'X';
        }
    }
    if (strlen(processed) % 2 != 0) {
        processed[strlen(processed)] = 'X';
        processed[strlen(processed) + 1] = '\0';
    }
    strcpy(text, processed);
}
void playfairCipher(char *text, int encrypt) {
    int i;
    preprocessText(text);
    for (i = 0; i < strlen(text); i += 2) {
        processPair(&text[i], &text[i + 1], encrypt);
    }
}
int main() {
    char key[30], text[100];
    int choice;
    printf("Enter the key for the Playfair cipher: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    printf("Enter the text to encrypt/decrypt: ");
    fgets(text, sizeof(text), stdin);
    text[strcspn(text, "\n")] = '\0';
    createMatrix(key);
    printf("Choose an option:\n1. Encrypt\n2. Decrypt\nEnter your choice: ");
    scanf("%d", &choice);
    if (choice == 1) {
        playfairCipher(text, 1);
        printf("Encrypted text: %s\n", text);
    } else if (choice == 2) {
        playfairCipher(text, 0);
        printf("Decrypted text: %s\n", text);
    } else {
        printf("Invalid choice!\n");
    }
    return 0;
}
