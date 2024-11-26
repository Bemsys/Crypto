#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
#define TOP_N 10  // Number of top plaintexts to return

// Expected letter frequency distribution for English (percentages)
float english_frequency[ALPHABET_SIZE] = {
    0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.060, 0.069, 0.002, 
    0.008, 0.040, 0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 
    0.028, 0.010, 0.023, 0.001, 0.020, 0.001
};

// Function to calculate letter frequency of a given ciphertext
void calculate_frequency(char *ciphertext, float *freq) {
    int length = strlen(ciphertext);
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        freq[i] = 0;
    }

    for (int i = 0; i < length; i++) {
        char c = tolower(ciphertext[i]);
        if (c >= 'a' && c <= 'z') {
            freq[c - 'a'] += 1;
        }
    }

    // Normalize the frequencies
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        freq[i] /= length;
    }
}

// Function to calculate the "distance" between the frequency of the ciphertext and the English language
float calculate_likelihood(float *ciphertext_freq) {
    float likelihood = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        likelihood += abs(ciphertext_freq[i] - english_frequency[i]);
    }
    return likelihood;
}

// Function to generate all possible substitutions based on a cipher key
void generate_substitution(char *ciphertext, char *substitution_key, char *plaintext) {
    int len = strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        char c = tolower(ciphertext[i]);
        if (c >= 'a' && c <= 'z') {
            plaintext[i] = substitution_key[c - 'a'];  // Replace with substituted letter
        } else {
            plaintext[i] = ciphertext[i];  // Copy non-alphabet characters directly
        }
    }
    plaintext[len] = '\0';
}

// Function to perform the letter frequency attack and rank possible plaintexts
void frequency_attack(char *ciphertext) {
    int length = strlen(ciphertext);
    float ciphertext_freq[ALPHABET_SIZE];
    calculate_frequency(ciphertext, ciphertext_freq);

    // Array to store the likelihood of each possible substitution
    float likelihoods[ALPHABET_SIZE];
    char possible_plaintexts[ALPHABET_SIZE][length + 1];

    // Try all possible substitutions (using the sorted frequencies of letters)
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        char substitution_key[ALPHABET_SIZE];
        char available_letters[ALPHABET_SIZE];
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            available_letters[j] = 'a' + j;  // Store all available letters
        }

        // Create a substitution key by sorting letters based on frequency (approximation)
        // Here, we are assigning letters based on frequency rank, this is a simplification
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            substitution_key[j] = available_letters[(i + j) % ALPHABET_SIZE];
        }

        // Decrypt the ciphertext using the current substitution key
        generate_substitution(ciphertext, substitution_key, possible_plaintexts[i]);

        // Calculate the likelihood of this decryption
        likelihoods[i] = calculate_likelihood(ciphertext_freq);
        printf("Substitution %d, Likelihood: %.5f, Plaintext: %s\n", i, likelihoods[i], possible_plaintexts[i]);
    }

    // Sorting the shifts based on likelihoods in descending order
    for (int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (int j = i + 1; j < ALPHABET_SIZE; j++) {
            if (likelihoods[i] < likelihoods[j]) {
                float temp = likelihoods[i];
                likelihoods[i] = likelihoods[j];
                likelihoods[j] = temp;

                char temp_text[length + 1];
                strcpy(temp_text, possible_plaintexts[i]);
                strcpy(possible_plaintexts[i], possible_plaintexts[j]);
                strcpy(possible_plaintexts[j], temp_text);
            }
        }
    }

    // Display the top N likely plaintexts
    printf("\nTop %d Possible Plaintexts:\n", TOP_N);
    for (int i = 0; i < TOP_N; i++) {
        printf("%d: %s (Likelihood: %.5f)\n", i + 1, possible_plaintexts[i], likelihoods[i]);
    }
}

int main() {
    char ciphertext[] = "Uifsf jt b tfdsfu dpef!";  // Example ciphertext, which is "There is a secret code!"

    printf("Ciphertext: %s\n", ciphertext);
    frequency_attack(ciphertext);
    
    return 0;
}

