#include <stdio.h>
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
void factorize_n(int n, int phi, int *p, int *q) {
	int i;
    for (i = 2; i < n; i++) {
        if (n % i == 0) {
            int j = n / i;
            if ((i - 1) * (j - 1) == phi) {
                *p = i;
                *q = j;
                return;
            }
        }
    }
}
int main() {
    int n = 3599;
    int e = 31;
    int d = 2687;
    int phi = (d * e - 1);
    int k = 1;
    while (phi % k != 0) {
        k++;
    }
    phi /= k;
    printf("f(n) = %d\n", phi);
    int p, q;
    factorize_n(n, phi, &p, &q);
    printf("Factors of n: p = %d, q = %d\n", p, q);
    printf("If Bob generates a new key pair using the same n, it will still be compromised because p and q are known.\n");
    return 0;
}
