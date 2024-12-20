#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define MATRIX_SIZE 5
char playfairMatrix[MATRIX_SIZE][MATRIX_SIZE];
void prepareKeyword(const char *keyword, char *keyTable) {
	int i;
	char ch;
    int used[26] = {0};
    int idx = 0;
    for (i = 0; keyword[i] != '\0'; i++) {
        char ch = toupper(keyword[i]);
        if (ch == 'J') ch = 'I';
        if (!used[ch - 'A']) {
            keyTable[idx++] = ch;
            used[ch - 'A'] = 1;
        }
    }
    for (ch = 'A'; ch <= 'Z'; ch++) {
        if (ch == 'J') continue;
        if (!used[ch - 'A']) {
            keyTable[idx++] = ch;
            used[ch - 'A'] = 1;
        }
    }
    keyTable[idx] = '\0';
}
void createMatrix(const char *keyTable) {
	int i,j;
    int idx = 0;
    for (i = 0; i < MATRIX_SIZE; i++) {
        for (j = 0; j < MATRIX_SIZE; j++) {
            playfairMatrix[i][j] = keyTable[idx++];
        }
    }
}
void locateChar(char ch, int *row, int *col) {
	int i,j;
    for (i = 0; i < MATRIX_SIZE; i++) {
        for (j = 0; j < MATRIX_SIZE; j++) {
            if (playfairMatrix[i][j] == ch) {
                *row = i;
                *col = j;
                return;
            }
        }
    }
}
void decryptPair(char a, char b, char *decryptedPair) {
    int row1, col1, row2, col2;
    locateChar(a, &row1, &col1);
    locateChar(b, &row2, &col2);
    if (row1 == row2) {
        decryptedPair[0] = playfairMatrix[row1][(col1 + MATRIX_SIZE - 1) % MATRIX_SIZE];
        decryptedPair[1] = playfairMatrix[row2][(col2 + MATRIX_SIZE - 1) % MATRIX_SIZE];
    } else if (col1 == col2) {
        decryptedPair[0] = playfairMatrix[(row1 + MATRIX_SIZE - 1) % MATRIX_SIZE][col1];
        decryptedPair[1] = playfairMatrix[(row2 + MATRIX_SIZE - 1) % MATRIX_SIZE][col2];
    } else {
        decryptedPair[0] = playfairMatrix[row1][col2];
        decryptedPair[1] = playfairMatrix[row2][col1];
    }
}
void decryptMessage(const char *ciphertext, char *plaintext) {
	int i;
    char decryptedPair[3];
    decryptedPair[2] = '\0';
    int idx = 0;
    for (i = 0; i < strlen(ciphertext); i += 2) {
        decryptPair(ciphertext[i], ciphertext[i + 1], decryptedPair);
        plaintext[idx++] = decryptedPair[0];
        plaintext[idx++] = decryptedPair[1];
    }
    plaintext[idx] = '\0';
}
int main() {
	int i,j;
    const char keyword[] = "PLAYFAIR";
    char keyTable[26];
    char plaintext[1024];
    prepareKeyword(keyword, keyTable);
    createMatrix(keyTable);
    printf("Playfair Matrix:\n");
    for (i = 0; i < MATRIX_SIZE; i++) {
        for (j = 0; j < MATRIX_SIZE; j++) {
            printf("%c ", playfairMatrix[i][j]);
        }
        printf("\n");
    }
    const char ciphertext[] = "KXJEYUREBEZWEHEWRYTUHEYFSKREHEGOYFIWTTTUOLKSYCAJPOBOTEIZONTXBYBNTGONEYC"
                              "UZWRGDSONSXBOUYWRHEBAAHYUSEDQ";
    decryptMessage(ciphertext, plaintext);
    printf("\nCiphertext: %s\n", ciphertext);
    printf("Decrypted Message: %s\n", plaintext);
    return 0;
}
