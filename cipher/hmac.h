#ifndef _CIPHER_HMAC_ALL_H
#define _CIPHER_HMAC_ALL_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

#define   SHA1_DIGEST_SIZE  20
#define SHA224_DIGEST_SIZE  28
#define SHA256_DIGEST_SIZE  32
#define SHA384_DIGEST_SIZE  48
#define SHA512_DIGEST_SIZE  64
#define    MD5_DIGEST_SIZE  16
    void hmac_md5(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
    void hmac_sha1(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
    void hmac_sha224(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
    void hmac_sha256(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
    void hmac_sha384(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);
    void hmac_sha512(unsigned char *key, int key_len,
        unsigned char *text, int text_len, unsigned char *hmac);

#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_HMAC_ALL_H */
