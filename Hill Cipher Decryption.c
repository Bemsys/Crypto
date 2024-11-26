#include <stdio.h>
#include <math.h>
unsigned long long factorial(int n) {
	int i;
    unsigned long long result = 1;
    for (i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}
int main() {
    int letters = 25;
    unsigned long long total_keys = factorial(letters);
    double total_keys_log2 = log2(total_keys);
    double unique_keys_log2 = total_keys_log2 - 5.8;    
    printf("Total keys: %.0f (approx. 2^%.1f)\n", (double)total_keys, total_keys_log2);
    printf("Effective unique keys: approx. 2^%.1f\n", unique_keys_log2); 
    return 0;
}
