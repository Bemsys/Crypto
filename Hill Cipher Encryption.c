#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define MATRIX_SIZE 5
char playfairMatrix[MATRIX_SIZE][MATRIX_SIZE] = {
    {'M', 'F', 'H', 'I', 'K'},
    {'U', 'N', 'O', 'P', 'Q'},
    {'Z', 'V', 'W', 'X', 'Y'},
    {'E', 'L', 'A', 'R', 'G'},
    {'D', 'S', 'T', 'B', 'C'}
};
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
void preparePlaintext(const char *input, char *output) {
    int idx = 0;
    char lastChar = '\0';
    int i;
    for (i = 0; input[i] != '\0'; i++) {
        if (isalpha(input[i])) {
            char ch = toupper(input[i]);
            if (ch == 'J') ch = 'I';
            if (idx > 0 && ch == lastChar) {
                output[idx++] = 'X';
            }
            output[idx++] = ch;
            lastChar = ch;
        }
    }
    if (idx % 2 != 0) {
        output[idx++] = 'X';
    }
    output[idx] = '\0';
}
void encryptPair(char a, char b, char *encryptedPair) {
    int row1, col1, row2, col2;
    locateChar(a, &row1, &col1);
    locateChar(b, &row2, &col2);

    if (row1 == row2) {
        encryptedPair[0] = playfairMatrix[row1][(col1 + 1) % MATRIX_SIZE];
        encryptedPair[1] = playfairMatrix[row2][(col2 + 1) % MATRIX_SIZE];
    } else if (col1 == col2) {
        encryptedPair[0] = playfairMatrix[(row1 + 1) % MATRIX_SIZE][col1];
        encryptedPair[1] = playfairMatrix[(row2 + 1) % MATRIX_SIZE][col2];
    } else {
        encryptedPair[0] = playfairMatrix[row1][col2];
        encryptedPair[1] = playfairMatrix[row2][col1];
    }
}

// Function to encrypt the plaintext
void encryptMessage(const char *plaintext, char *ciphertext) {
    char encryptedPair[3];
    encryptedPair[2] = '\0';
    int i;
    int idx = 0;
    for (i = 0; i < strlen(plaintext); i += 2) {
        encryptPair(plaintext[i], plaintext[i + 1], encryptedPair);
        ciphertext[idx++] = encryptedPair[0];
        ciphertext[idx++] = encryptedPair[1];
    }
    ciphertext[idx] = '\0';
}
int main() {
    const char plaintext[] = "Must see you over Cadogan West. Coming at once.";
    char preparedText[1024];
    char ciphertext[1024];
    preparePlaintext(plaintext, preparedText);
    printf("Prepared Plaintext: %s\n", preparedText);
    encryptMessage(preparedText, ciphertext);
    printf("Ciphertext: %s\n", ciphertext);
    return 0;
}
