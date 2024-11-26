#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define ALPHABET_SIZE 26
const double english_frequencies[ALPHABET_SIZE] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074
};
void compute_frequencies(const char ciphertext[], int letter_counts[]) {
	int i;
    for (i = 0; i < ALPHABET_SIZE; i++) {
        letter_counts[i] = 0;
    }
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            letter_counts[ciphertext[i] - 'a']++;
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            letter_counts[ciphertext[i] - 'A']++;
        }
    }
}
void sort_by_frequency(int letter_counts[], int sorted_indices[]) {
	int i,j;
    for (i = 0; i < ALPHABET_SIZE; i++) {
        sorted_indices[i] = i;
    }

    for (i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (j = i + 1; j < ALPHABET_SIZE; j++) {
            if (letter_counts[sorted_indices[j]] > letter_counts[sorted_indices[i]]) {
                int temp = sorted_indices[i];
                sorted_indices[i] = sorted_indices[j];
                sorted_indices[j] = temp;
            }
        }
    }
}
void substitute(const char ciphertext[], char plaintext[], const char mapping[]) {
	int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = mapping[ciphertext[i] - 'a'];
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = mapping[ciphertext[i] - 'A'];
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
}
void generate_mapping(int sorted_indices[], char mapping[]) {
	int i;
    const char english_order[] = "etaoinshrdlcumwfgypbvkjxqz";
    for (i = 0; i < ALPHABET_SIZE; i++) {
        mapping[sorted_indices[i]] = english_order[i];
    }
}
int main() {
    char ciphertext[500], plaintext[500];
    int letter_counts[ALPHABET_SIZE], sorted_indices[ALPHABET_SIZE];
    char mapping[ALPHABET_SIZE];
    printf("Enter ciphertext: ");
    fgets(ciphertext, sizeof(ciphertext), stdin);
    ciphertext[strcspn(ciphertext, "\n")] = '\0';
    compute_frequencies(ciphertext, letter_counts);
    sort_by_frequency(letter_counts, sorted_indices);
    generate_mapping(sorted_indices, mapping);
    substitute(ciphertext, plaintext, mapping);
    printf("\nPossible plaintext:\n%s\n", plaintext);
    return 0;
}
