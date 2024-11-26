#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

// Frequency of letters in English (approximate)
double english_freq[ALPHABET_SIZE] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};

// Function to clean and normalize the ciphertext (convert to uppercase, ignore non-alphabetic characters)
void clean_ciphertext(char* ciphertext, char* cleaned) {
    int i, j = 0;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            cleaned[j++] = toupper(ciphertext[i]);
        }
    }
    cleaned[j] = '\0';
}

// Function to count the frequency of each letter in the ciphertext
void count_frequency(char* ciphertext, int* freq) {
    int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            freq[toupper(ciphertext[i]) - 'A']++;
        }
    }
}

// Function to generate the possible substitution based on frequency analysis
void generate_substitution(int* freq, char* substitution) {
    char alphabet[ALPHABET_SIZE] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int i, j;

    // Create an array of indices based on frequency (descending order)
    int freq_sorted[ALPHABET_SIZE];
    char sorted_ciphertext[ALPHABET_SIZE];
    
    // Copy the frequencies and alphabet into new arrays for sorting
    for (i = 0; i < ALPHABET_SIZE; i++) {
        freq_sorted[i] = freq[i];
        sorted_ciphertext[i] = alphabet[i];
    }

    // Sort the frequency array along with the alphabet array (descending order)
    for (i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (j = i + 1; j < ALPHABET_SIZE; j++) {
            if (freq_sorted[i] < freq_sorted[j]) {
                // Swap frequencies
                int temp = freq_sorted[i];
                freq_sorted[i] = freq_sorted[j];
                freq_sorted[j] = temp;

                // Swap corresponding alphabet letters
                char temp_char = sorted_ciphertext[i];
                sorted_ciphertext[i] = sorted_ciphertext[j];
                sorted_ciphertext[j] = temp_char;
            }
        }
    }

    // Manually adjusting the mapping for better decryption (common letters)
    char english_alphabet[ALPHABET_SIZE] = "ETAOINSHRDLCUMWFBYPVKGJQXZ"; // Common letter frequencies

    // Map the sorted ciphertext letters to the sorted English letters based on their frequencies
    for (i = 0; i < ALPHABET_SIZE; i++) {
        substitution[sorted_ciphertext[i] - 'A'] = english_alphabet[i];
    }
}

// Function to apply the substitution cipher and generate the plaintext
void apply_substitution(char* ciphertext, char* substitution, char* plaintext) {
    int i;
    for (i = 0; ciphertext[i] != '\0'; i++) {
        if (isalpha(ciphertext[i])) {
            plaintext[i] = substitution[toupper(ciphertext[i]) - 'A'];
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[i] = '\0';
}

// Function to display the top N plaintexts
void display_top_plaintexts(char* ciphertext, int top_n) {
    int freq[ALPHABET_SIZE] = {0};
    char cleaned_ciphertext[strlen(ciphertext) + 1];
    clean_ciphertext(ciphertext, cleaned_ciphertext);

    count_frequency(cleaned_ciphertext, freq);

    char substitution[ALPHABET_SIZE] = {0};
    generate_substitution(freq, substitution);

    char plaintext[strlen(ciphertext) + 1];
    apply_substitution(ciphertext, substitution, plaintext);

    printf("Generated Plaintext: %s\n", plaintext);
}

int main() {
    char ciphertext[] = "Wklv lv d whvw phvvdjh"; // Sample ciphertext

    int top_n = 1;

    printf("Ciphertext: %s\n", ciphertext);

    display_top_plaintexts(ciphertext, top_n);

    return 0;
}

