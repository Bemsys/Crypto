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
    int e = 31;
    int n = 3599;
    int p = 59;
    int q = 61;
    printf("p = %d, q = %d\n", p, q);
    int phi = (p - 1) * (q - 1);
    printf("f(n) = %d\n", phi);
    int d = modular_inverse(e, phi);
    if (d == -1) {
        printf("Error: No modular inverse found for e = %d mod f(n) = %d\n", e, phi);
        return 1;
    }
    printf("Private key (d) = %d\n", d);
    return 0;
}
