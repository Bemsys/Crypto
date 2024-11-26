#include <stdio.h>
#include <stdint.h>
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}
int main() {
    uint64_t p = 3599;
    uint64_t a = 2;
    uint64_t x_A = 1234;
    uint64_t A = mod_exp(a, x_A, p);
    uint64_t x_B = 5678;
    uint64_t B = mod_exp(a, x_B, p);
    uint64_t S_A = mod_exp(B, x_A, p);
    uint64_t S_B = mod_exp(A, x_B, p);
    printf("Alice's Public Key: %llu\n", A);
    printf("Bob's Public Key: %llu\n", B);
    printf("Alice's Shared Secret: %llu\n", S_A);
    printf("Bob's Shared Secret: %llu\n", S_B);
    if (S_A == S_B) {
        printf("Shared secret established!\n");
    } else {
        printf("Error: Shared secret mismatch.\n");
    }
    return 0;
}
