#include <stdint.h>

#include "tea.h"

uint32_t UnpackUint32(
        unsigned char *b
) {
    return (uint32_t) b[0] | (uint32_t) b[1] << 8 | (uint32_t) b[2] << 16 | (uint32_t) b[3] << 24;

}

void PackUint32(
        unsigned char *dst,
        uint32_t n
) {
    dst[0] = n;
    dst[1] = n >> 8;
    dst[2] = n >> 16;
    dst[3] = n >> 24;
    return;
}

void EncryptBlock(
        uint32_t *v,
        uint32_t *k
) {
    uint32_t delta = 0x9e3779b9, sum = 0, i;
    i = 0;

    do {
        sum += delta;
        v[0] += ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        v[1] += ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
        i++;
    } while (i < 32);
}

void TeaEncryptCBC(
        unsigned char *crypted_text,
        unsigned char *plain_text,
        int len,
        unsigned char iv[8],
        unsigned char key[16]
) {
    unsigned char *src = plain_text;
    unsigned char *dst = crypted_text;
    unsigned char padded[8];
    uint32_t v[2], k[4];
    int i;
    v[0] = UnpackUint32(&iv[0]);
    v[1] = UnpackUint32(&iv[4]);
    k[0] = UnpackUint32(&key[0]);
    k[1] = UnpackUint32(&key[4]);
    k[2] = UnpackUint32(&key[8]);
    k[3] = UnpackUint32(&key[12]);


    do {
        v[0] ^= UnpackUint32(&src[0]);
        v[1] ^= UnpackUint32(&src[4]);

        EncryptBlock(v, k);

        PackUint32(&dst[0], v[0]);
        PackUint32(&dst[4], v[1]);

        src += 8;
        dst += 8;
        len -= 8;
    } while (len >= 8);

    i = 0;
    do {
        padded[i] = src[i];
        i++;
    } while (i < len);

    i = len;
    do {
        padded[i] = 8 - len;
        i++;
    } while (i < 8);
    v[0] ^= UnpackUint32(&padded[0]);
    v[1] ^= UnpackUint32(&padded[4]);

    EncryptBlock(v, k);

    PackUint32(&dst[0], v[0]);
    PackUint32(&dst[4], v[1]);
}

void DecryptBlock(
        uint32_t *v,
        uint32_t *k
) {
    uint32_t delta = 0x9e3779b9, sum = 0xc6ef3720, i;
    i = 0;
    do {
        v[1] -= ((v[0] << 4) + k[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + k[3]);
        v[0] -= ((v[1] << 4) + k[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + k[1]);
        sum -= delta;
        i++;
    } while (i < 32);
}

int TeaDecryptCBC(
        unsigned char *crypted_text,
        unsigned char *plain_text,
        int len,
        unsigned char iv[8],
        unsigned char key[16]
) {
    unsigned char *dst = crypted_text;
    unsigned char *src = plain_text;
    unsigned char padded[8];
    uint32_t v[2], prev[2], tmp[2], k[4];
    int i;
    prev[0] = UnpackUint32(&iv[0]);
    prev[1] = UnpackUint32(&iv[4]);
    k[0] = UnpackUint32(&key[0]);
    k[1] = UnpackUint32(&key[4]);
    k[2] = UnpackUint32(&key[8]);
    k[3] = UnpackUint32(&key[12]);

    do {
        v[0] = tmp[0] = UnpackUint32(&src[0]);
        v[1] = tmp[1] = UnpackUint32(&src[4]);

        DecryptBlock(v, k);

        PackUint32(&dst[0], v[0] ^ prev[0]);
        PackUint32(&dst[4], v[1] ^ prev[1]);

        prev[0] = tmp[0];
        prev[1] = tmp[1];

        src += 8;
        dst += 8;
        len -= 8;
    } while (len > 8);

    if (len == 8) {
        v[0] = UnpackUint32(&src[0]);
        v[1] = UnpackUint32(&src[4]);

        DecryptBlock(v, k);

        PackUint32(&padded[0], v[0] ^ prev[0]);
        PackUint32(&padded[4], v[1] ^ prev[1]);
    } else {
        return -1;
    }

    if (padded[7] <= 8) {
        i = 0;
    } else {
        return -1;
    }

    do {
        dst[i] = padded[i];
        i++;
    } while (i < 8 - padded[7]);
    return 0;
}
