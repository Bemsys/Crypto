#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define MESSAGE "Hello, this is a test message."
#define MESSAGE_SIZE 32
typedef unsigned char byte;
void rsa_sign(byte *message_hash, byte *signature) {
    int i;
    for (i = 0; i < MESSAGE_SIZE; i++) {
        signature[i] = message_hash[i];
    }
}
void dsa_sign(byte *message_hash, byte *signature) {
    int i;
    byte k = rand() % 256;
    for (i = 0; i < MESSAGE_SIZE; i++) {
        signature[i] = message_hash[i] ^ k;
    }
}
void hash_message(const char *message, byte *message_hash) {
	int i;
    for ( i = 0; i < MESSAGE_SIZE; i++) {
        message_hash[i] = message[i % strlen(message)];
    }
}
void print_signature(byte *signature) {
	int i;
    for (i = 0; i < MESSAGE_SIZE; i++) {
        printf("%02x ", signature[i]);
    }
    printf("\n");
}
int main() {
    srand(time(NULL));
    byte message_hash[MESSAGE_SIZE];
    byte rsa_signature[MESSAGE_SIZE];
    byte dsa_signature1[MESSAGE_SIZE];
    byte dsa_signature2[MESSAGE_SIZE];
    hash_message(MESSAGE, message_hash);
    rsa_sign(message_hash, rsa_signature);
    printf("RSA Signature: ");
    print_signature(rsa_signature);
    dsa_sign(message_hash, dsa_signature1);
    printf("DSA Signature 1: ");
    print_signature(dsa_signature1);
    dsa_sign(message_hash, dsa_signature2);
    printf("DSA Signature 2: ");
    print_signature(dsa_signature2);
    return 0;
}
