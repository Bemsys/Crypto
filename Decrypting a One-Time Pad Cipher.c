#include <stdio.h>
#include <string.h>
#define MOD 26
int mod_inverse(int a, int mod) {
	int x;
    a = a % mod;
    for (x = 1; x < mod; x++) {
        if ((a * x) % mod == 1)
            return x;
    }
    return -1;
}
int determinant_mod26(int matrix[2][2]) {
    int det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % MOD;
    if (det < 0) det += MOD;
    return det;
}
void inverse_matrix_mod26(int matrix[2][2], int inv_matrix[2][2]) {
	int i,j;
    int det = determinant_mod26(matrix);
    int det_inv = mod_inverse(det, MOD);
    if (det_inv == -1) {
        printf("Matrix is not invertible modulo %d\n", MOD);
        return;
    }
    inv_matrix[0][0] = matrix[1][1];
    inv_matrix[1][1] = matrix[0][0];
    inv_matrix[0][1] = -matrix[0][1];
    inv_matrix[1][0] = -matrix[1][0];
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 2; j++) {
            inv_matrix[i][j] = (inv_matrix[i][j] * det_inv) % MOD;
            if (inv_matrix[i][j] < 0) inv_matrix[i][j] += MOD;
        }
    }
}
void matrix_multiply_mod26(int A[2][2], int B[2][2], int result[2][2]) {
	int i,j,k;
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 2; j++) {
            result[i][j] = 0;
            for (k = 0; k < 2; k++) {
                result[i][j] += A[i][k] * B[k][j];
            }
            result[i][j] %= MOD;
        }
    }
}
int main() {
	int i,j;
    int plaintext[2][2] = {{7, 8}, {11, 25}};
    int ciphertext[2][2] = {{19, 23}, {0, 14}};
    int plaintext_inverse[2][2];
    inverse_matrix_mod26(plaintext, plaintext_inverse);
    int key[2][2];
    matrix_multiply_mod26(plaintext_inverse, ciphertext, key);
    printf("Recovered Key Matrix:\n");
    for (i = 0; i < 2; i++) {
        for (j = 0; j < 2; j++) {
            printf("%d ", key[i][j]);
        }
        printf("\n");
    }
    return 0;
}
