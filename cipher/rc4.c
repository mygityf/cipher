#include "rc4.h"

#define RC4_SIZE 256
void rc4_setup(unsigned char *s,
    unsigned char *key, unsigned int Len) {
    int i = 0, j = 0;
    char k[RC4_SIZE] = { 0 };
    unsigned char tmp = 0;
    for (i = 0; i < RC4_SIZE; i++) {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i = 0; i < RC4_SIZE; i++) {
        j = (j + s[i] + k[i]) % RC4_SIZE;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void rc4_crypt(unsigned char *s,
    unsigned char *data, unsigned int Len) {
    int i = 0, j = 0, t = 0;
    unsigned int k = 0;
    unsigned char tmp;
    for (k = 0; k < Len; k++) {
        i = (i + 1) % RC4_SIZE;
        j = (j + s[i]) % RC4_SIZE;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % RC4_SIZE;
        data[k] ^= s[t];
    }
}

void RC4_Sample(unsigned char *key, int key_len,
    unsigned char *data, int data_len) {
    char sbox[RC4_SIZE] = { 0 };
    rc4_setup(sbox, key, key_len);
    rc4_crypt(sbox, data, data_len);
}