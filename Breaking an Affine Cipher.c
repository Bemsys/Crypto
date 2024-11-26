#include <stdio.h>
#include <ctype.h>
int modInverse(int a, int m) {
	int x;
    for (x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1;
}
char decryptChar(char c, int a_inverse, int b) {
    if (isalpha(c)) {
        int x = toupper(c) - 'A';
        int decrypted = (a_inverse * (x - b + 26)) % 26;
        return (char)(decrypted + 'A');
    }
    return c;
}
void decryptAffineCipher(const char *ciphertext, int a, int b) {
	int i;
    int a_inverse = modInverse(a, 26);
    if (a_inverse == -1) {
        printf("Invalid 'a' value, no modular inverse exists.\n");
        return;
    }
    printf("Decrypted text: ");
    for (i = 0; ciphertext[i] != '\0'; i++) {
        printf("%c", decryptChar(ciphertext[i], a_inverse, b));
    }
    printf("\n");
}
int main() {
    char mostFreqCipher = 'B';
    char secondFreqCipher = 'U';
    char mostFreqPlain = 'E';
    char secondFreqPlain = 'T';
    int cipher1 = mostFreqCipher - 'A';
    int cipher2 = secondFreqCipher - 'A';
    int plain1 = mostFreqPlain - 'A';
    int plain2 = secondFreqPlain - 'A';
    int a = (plain1 - plain2) * modInverse((cipher1 - cipher2 + 26) % 26, 26) % 26;
    if (a < 0) a += 26;
    int b = (plain1 - a * cipher1 + 26) % 26;
    printf("Key values: a = %d, b = %d\n", a, b);
    const char *ciphertext = "BUPPHRQUB";
    decryptAffineCipher(ciphertext, a, b);
    return 0;
}
