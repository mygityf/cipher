#include <string.h>
#include "sha224.h"

void SHA224_Core_Init(SHA256_State *s) {
    s->h[0] = 0xc1059ed8ul;
    s->h[1] = 0x367cd507ul;
    s->h[2] = 0x3070dd17ul;
    s->h[3] = 0xf70e5939ul;
    s->h[4] = 0xffc00b31ul;
    s->h[5] = 0x68581511ul;
    s->h[6] = 0x64f98fa7ul;
    s->h[7] = 0xbefa4fa4ul;
}

#define SHA224_DIGEST_SIZE  28

void SHA224_Init(SHA256_State *s) {
    SHA224_Core_Init(s);
    s->blkused = 0;
    s->lenhi = s->lenlo = 0;
}

void SHA224_Bytes(SHA256_State *s, const void *p, int len) {
    SHA256_Bytes(s, p, len);
}

void SHA224_Final(SHA256_State *s, unsigned char *digest) {
    SHA256_Final(s, digest);
    digest[SHA224_DIGEST_SIZE] = 0x00;
}

void SHA224_Simple(const void *p, int len, unsigned char *output) {
    SHA256_State s;

    SHA224_Init(&s);
    SHA224_Bytes(&s, p, len);
    SHA224_Final(&s, output);
}
