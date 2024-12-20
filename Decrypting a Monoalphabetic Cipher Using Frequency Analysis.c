#include <stdio.h>
#include <string.h>
#include <ctype.h>
#define MAX_TEXT_SIZE 1024
void calculateFrequencies(const char *text, int *freq) {
	int i;
    for (i = 0; text[i] != '\0'; i++) {
        if (isprint(text[i])) {
            freq[(unsigned char)text[i]]++;
        }
    }
}
void displayFrequencies(int *freq) {
	int i;
    printf("\nCharacter Frequencies:\n");
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0 && isprint(i)) {
            printf("'%c': %d\n", i, freq[i]);
        }
    }
}
void decrypt(const char *ciphertext, const char *substitution) {
	int i;
    printf("\nDecrypted Message:\n");
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isprint(ciphertext[i])) {
            char decryptedChar = substitution[(unsigned char)ciphertext[i]];
            printf("%c", decryptedChar ? decryptedChar : ciphertext[i]);
        } else {
            printf("%c", ciphertext[i]);
        }
    }
    printf("\n");
}
int main() {
    const char ciphertext[] =
        "53���305))6*;4826)4�.)4�);806*;48�8�60))85;;]8*;:�*8�83"
        "(88)5*�;46(;88*96*?;8)*�(;485);5*�2:*�(;4956*2(5*�4)8�8*"
        ";4069285);)6�8)4��;1(�9;48081;8:8�1;48�85;4)485�528806*81"
        "(�9;48;(88;4(�?34;48)4�;161;:188;�?;";
    int freq[256] = {0};
    calculateFrequencies(ciphertext, freq);
    displayFrequencies(freq);
    char substitution[256] = {0};
    substitution['�'] = 'e';
    substitution[';'] = 't';
    substitution['*'] = 'h';
    substitution['5'] = 'a';
    substitution['8'] = 'o';
    substitution['4'] = 'i';
    substitution['6'] = 'n';
    substitution['0'] = 's';
    substitution['9'] = 'r';
    substitution['3'] = 'd';
    substitution['�'] = 'l';
    substitution[')'] = 'u';
    substitution['('] = 'm';
    substitution[':'] = 'y';
    substitution['?'] = 'g';
    decrypt(ciphertext, substitution);
    return 0;
}
