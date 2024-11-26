#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define ALPHABET_SIZE 26
const double english_frequencies[ALPHABET_SIZE] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
};
double compute_score(const char plaintext[]) {
	int i;
    int counts[ALPHABET_SIZE] = {0};
    int total_letters = 0;
    double score = 0.0;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            counts[plaintext[i] - 'a']++;
            total_letters++;
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            counts[plaintext[i] - 'A']++;
            total_letters++;
        }
    }
    for (i = 0; i < ALPHABET_SIZE; i++) {
        double observed_frequency = (double)counts[i] / total_letters * 100;
        score += observed_frequency * english_frequencies[i];
    }

    return score;
}
void decrypt_with_key(const char ciphertext[], char plaintext[], int key) {
	int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = ((ciphertext[i] - 'a' - key + ALPHABET_SIZE) % ALPHABET_SIZE) + 'a';
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = ((ciphertext[i] - 'A' - key + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
int main() {
	int key,i;
    char ciphertext[100], plaintext[100];
    double scores[ALPHABET_SIZE];
    int top_keys[10];
    printf("Enter ciphertext: ");
    fgets(ciphertext, sizeof(ciphertext), stdin);
    ciphertext[strcspn(ciphertext, "\n")] = '\0';
    for (key = 0; key < ALPHABET_SIZE; key++) {
        decrypt_with_key(ciphertext, plaintext, key);
        scores[key] = compute_score(plaintext);
    }
    for (i = 0; i < 10; i++) {
        double max_score = -1.0;
        int max_key = -1;
        for (key = 0; key < ALPHABET_SIZE; key++) {
            if (scores[key] > max_score) {
                max_score = scores[key];
                max_key = key;
            }
        }
        top_keys[i] = max_key;
        scores[max_key] = -1.0;
    }
    printf("\nTop 10 Possible Plaintexts:\n");
    for (i = 0; i < 10; i++) {
        decrypt_with_key(ciphertext, plaintext, top_keys[i]);
        printf("Key %2d: %s\n", top_keys[i], plaintext);
    }
    return 0;
}
