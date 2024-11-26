#include <stdio.h>
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}
int modular_inverse(int e, int phi) {
    int t = 0, newt = 1;
    int r = phi, newr = e;
    while (newr != 0) {
        int quotient = r / newr;
        int temp = t;
        t = newt;
        newt = temp - quotient * newt;
        int temp_r = r;
        r = newr;
        newr = temp_r - quotient * newr;
    }
    if (r > 1) return -1;
    if (t < 0) t += phi;
    return t;
}
int main() {
    int n = 3599;
    int e = 31;
    int m = 177;
    int p = gcd(m, n);
    if (p == 1 || p == n) {
        printf("No useful information from the given plaintext block.\n");
        return 1;
    }
    int q = n / p;
    printf("Found factors: p = %d, q = %d\n", p, q);
    int phi = (p - 1) * (q - 1);
    printf("f(n) = %d\n", phi);
    int d = modular_inverse(e, phi);
    if (d == -1) {
        printf("Error: Could not compute modular inverse.\n");
        return 1;
    }
    printf("Private key (d) = %d\n", d);
    return 0;
}
