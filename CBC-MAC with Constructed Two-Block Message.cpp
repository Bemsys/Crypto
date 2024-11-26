#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 2  // Size of the matrix (2x2 Hill cipher)

void printMatrix(int mat[SIZE][SIZE]) {
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            printf("%d ", mat[i][j]);
        }
        printf("\n");
    }
}

// Function to find the inverse of a matrix modulo 26
int modInverse(int a, int m) {
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) {
            return x;
        }
    }
    return -1;  // No modular inverse exists
}

// Function to calculate the determinant of a 2x2 matrix modulo 26
int determinant(int mat[SIZE][SIZE]) {
    return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % 26;
}

// Function to calculate the inverse of a 2x2 matrix modulo 26
int inverseMatrix(int mat[SIZE][SIZE], int invMat[SIZE][SIZE]) {
    int det = determinant(mat);
    int detInv = modInverse(det, 26);
    
    if (detInv == -1) {
        printf("Matrix is not invertible modulo 26.\n");
        return 0;
    }

    invMat[0][0] = (detInv * mat[1][1]) % 26;
    invMat[0][1] = (-detInv * mat[0][1]) % 26;
    invMat[1][0] = (-detInv * mat[1][0]) % 26;
    invMat[1][1] = (detInv * mat[0][0]) % 26;

    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (invMat[i][j] < 0) {
                invMat[i][j] += 26;
            }
        }
    }
    return 1;
}

// Matrix multiplication modulo 26
void matrixMultiply(int A[SIZE][SIZE], int B[SIZE][SIZE], int result[SIZE][SIZE]) {
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            result[i][j] = 0;
            for (int k = 0; k < SIZE; k++) {
                result[i][j] += (A[i][k] * B[k][j]) % 26;
            }
            result[i][j] %= 26;
        }
    }
}

// Function to encrypt plaintext using the Hill cipher
void hillEncrypt(char* plaintext, int key[SIZE][SIZE], char* ciphertext) {
    int len = strlen(plaintext);
    for (int i = 0; i < len; i += SIZE) {
        int pt[SIZE];
        for (int j = 0; j < SIZE; j++) {
            pt[j] = plaintext[i + j] - 'A';  // Convert to integer (0-25)
        }

        int ct[SIZE] = {0};
        for (int j = 0; j < SIZE; j++) {
            for (int k = 0; k < SIZE; k++) {
                ct[j] += (key[j][k] * pt[k]) % 26;
            }
            ct[j] %= 26;
        }

        for (int j = 0; j < SIZE; j++) {
            ciphertext[i + j] = ct[j] + 'A';  // Convert back to characters
        }
    }
    ciphertext[len] = '\0';
}

// Function to solve for the key matrix using known plaintext-ciphertext pairs
void solveKeyMatrix(char* plaintext, char* ciphertext, int key[SIZE][SIZE]) {
    int pt[SIZE][SIZE], ct[SIZE][SIZE];
    
    // Convert plaintext and ciphertext to numeric matrices
    for (int i = 0; i < SIZE; i++) {
        pt[0][i] = plaintext[i] - 'A';
        ct[0][i] = ciphertext[i] - 'A';
    }

    for (int i = SIZE; i < SIZE * SIZE; i++) {
        pt[1][i % SIZE] = plaintext[i] - 'A';
        ct[1][i % SIZE] = ciphertext[i] - 'A';
    }

    // Calculate the inverse of the plaintext matrix modulo 26
    int ptInverse[SIZE][SIZE];
    if (!inverseMatrix(pt, ptInverse)) {
        printf("Cannot find inverse of the plaintext matrix.\n");
        return;
    }

    // Multiply the ciphertext matrix by the inverse of the plaintext matrix
    int temp[SIZE][SIZE];
    matrixMultiply(ct, ptInverse, temp);

    // The result is the key matrix
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            key[i][j] = temp[i][j];
        }
    }
}

int main() {
    char plaintext[] = "GDFD";  // Example plaintext
    char ciphertext[] = "SWQF";  // Example ciphertext after encryption
    
    int key[SIZE][SIZE];
    
    // Solve for the key matrix using known plaintext-ciphertext pairs
    solveKeyMatrix(plaintext, ciphertext, key);
    
    printf("Recovered key matrix:\n");
    printMatrix(key);
    
    // Encrypt the plaintext using the recovered key matrix
    char encryptedText[5];
    hillEncrypt(plaintext, key, encryptedText);
    
    printf("Encrypted text: %s\n", encryptedText);
    
    return 0;
}
