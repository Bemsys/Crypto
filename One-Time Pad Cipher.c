#include <stdio.h>
#include <string.h>
#define MOD 26
void encrypt_hill_cipher(char plaintext[], int key[2][2]) {
	int i;
    char ciphertext[100];
    int n = strlen(plaintext);
    if (n % 2 != 0) {
        plaintext[n] = 'x';
        plaintext[n + 1] = '\0';
        n++;
    }
    printf("Encrypted text: ");
    for (i = 0; i < n; i += 2) {
        int p1 = plaintext[i] - 'a';
        int p2 = plaintext[i + 1] - 'a';
        int c1 = (key[0][0] * p1 + key[0][1] * p2) % MOD;
        int c2 = (key[1][0] * p1 + key[1][1] * p2) % MOD;
        ciphertext[i] = c1 + 'a';
        ciphertext[i + 1] = c2 + 'a';
        printf("%c%c", ciphertext[i], ciphertext[i + 1]);
    }
    printf("\n");
}
int main() {
    char plaintext[] = "meetmeattheusualplaceattenratherthaneightoclock";
    int key[2][2] = {{9, 4}, {5, 7}};
    printf("Plaintext: %s\n", plaintext);
    encrypt_hill_cipher(plaintext, key);
    return 0;
}
