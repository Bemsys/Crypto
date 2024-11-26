#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 64
#define KEY_SIZE 56
#define SBOX_COUNT 8

// Initial Permutation (IP) for DES
int IP[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Inverse Initial Permutation (IP^-1)
int FP[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 62, 30,
    38, 6, 46, 14, 54, 22, 61, 29,
    37, 5, 45, 13, 53, 21, 60, 28,
    36, 4, 44, 12, 52, 20, 59, 27,
    35, 3, 43, 11, 51, 19, 58, 26,
    34, 2, 42, 10, 50, 18, 57, 25
};

// Permutation Choice 1 (PC-1)
int PC1[] = {
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4
};

// Permutation Choice 2 (PC-2)
int PC2[] = {
    13, 16, 10, 23, 0, 4, 2, 27,
    14, 5, 20, 9, 22, 18, 11, 3,
    25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39,
    50, 44, 32, 47, 43, 48, 38, 55,
    33, 52, 45, 41, 49, 35, 28, 31
};

// S-Boxes for DES
int S[8][4][16] = {
    // S1
    {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
     {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
     {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
     {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},

    // S2
    {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
     {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
     {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
     {13, 8, 10, 1, 15, 12, 9, 4, 5, 0, 15, 3, 2, 11, 14, 7}},

    // Additional S-boxes would follow here (S3 to S8)
};

// Function to apply permutation
uint64_t permute(uint64_t block, int *table, int size) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < size; i++) {
        result |= ((block >> (BLOCK_SIZE - table[i] - 1)) & 1) << (size - i - 1);
    }
    return result;
}

// Function to apply the left shift (for subkey generation)
uint64_t left_shift(uint64_t block, int shifts) {
    return ((block << shifts) | (block >> (28 - shifts))) & 0x0FFFFFFF;
}

// Key scheduling function
void generate_subkeys(uint64_t key, uint64_t subkeys[16]) {
    uint64_t permuted_key = permute(key, PC1, 56);
    
    uint64_t C = permuted_key >> 28;  // Left half (28 bits)
    uint64_t D = permuted_key & 0x0FFFFFFF;  // Right half (28 bits)
    int i;
    for (i = 0; i < 16; i++) {
        C = left_shift(C, 1);  // Left shift C
        D = left_shift(D, 1);  // Left shift D
        uint64_t combined = (C << 28) | D;
        subkeys[i] = permute(combined, PC2, 48);  // Apply PC-2 to generate subkey
    }
}

// DES function to encrypt/decrypt data
uint64_t des(uint64_t block, uint64_t subkeys[16], int decrypt) {
    block = permute(block, IP, 64);  // Initial permutation
    
    uint64_t L = block >> 32;  // Left half (32 bits)
    uint64_t R = block & 0xFFFFFFFF;  // Right half (32 bits)
    int round;
    for (round = 0; round < 16; round++) {
        uint64_t temp = R;
        
        // For encryption, use subkey[round]. For decryption, use subkey[15-round]
        uint64_t round_key = subkeys[decrypt ? 15 - round : round];
        
        // Feistel function (simplified, just XOR with subkey)
        uint64_t temp_R = R;
        R = L ^ round_key;  // XOR the left half with subkey
        
        // Perform S-box and permutation transformations here (simplified)
        R = temp_R ^ round_key;

        // Swap halves
        R = L ^ R;  // Swap L and R
        L = temp;  // Keep the previous R as L
    }

    block = (L << 32) | R;  // Combine left and right halves
    block = permute(block, FP, 64);  // Final permutation

    return block;
}

int main() {
    uint64_t key = 0x133457799BBCDFF1;  // Example 56-bit key
    uint64_t plaintext = 0x0123456789ABCDEF;  // Example 64-bit plaintext
    uint64_t ciphertext, decrypted_text;

    uint64_t subkeys[16];
    generate_subkeys(key, subkeys);  // Generate 16 subkeys for DES

    printf("Original plaintext: %016llX\n", plaintext);
    
    // Encrypt the plaintext
    ciphertext = des(plaintext, subkeys, 0);  // 0 for encryption
    printf("Ciphertext: %016llX\n", ciphertext);
    
    // Decrypt the ciphertext
    decrypted_text = des(ciphertext, subkeys, 1);  // 1 for decryption
    printf("Decrypted text: %016llX\n", plaintext);

    return 0;
}
