#include "sha384.h"

#define INIT(h,l) { h, l }

static void SHA384_Core_Init(SHA512_State *s) {
    static const uint64 iv[] = {
        INIT(0xcbbb9d5d, 0xc1059ed8), INIT(0x629a292a, 0x367cd507),
        INIT(0x9159015a, 0x3070dd17), INIT(0x152fecd8, 0xf70e5939),
        INIT(0x67332667, 0xffc00b31), INIT(0x8eb44a87, 0x68581511),
        INIT(0xdb0c2e0d, 0x64f98fa7), INIT(0x47b5481d, 0xbefa4fa4),
    };
    int i;
    for (i = 0; i < 8; i++)
        s->h[i] = iv[i];
}

void SHA384_Init(SHA512_State *s) {
    int i;
    SHA384_Core_Init(s);
    s->blkused = 0;
    for (i = 0; i < 4; i++)
        s->len[i] = 0;
}

void SHA384_Bytes(SHA512_State *s, const void *p, int len) {
    SHA512_Bytes(s, p, len);
}

#define SHA384_DIGEST_SIZE  48
void SHA384_Final(SHA512_State *s, unsigned char *digest) {
    SHA512_Final(s, digest);
    digest[SHA384_DIGEST_SIZE] = 0x00;
}

void SHA384_Simple(const void *p, int len, unsigned char *output) {
    SHA512_State s;

    SHA384_Init(&s);
    SHA384_Bytes(&s, p, len);
    SHA384_Final(&s, output);
}
