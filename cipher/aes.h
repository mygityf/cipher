#ifndef _CIPHER_AES_H
#define _CIPHER_AES_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

void aes256_encrypt_pubkey(unsigned char *key, unsigned char *blk, int len);
void aes256_decrypt_pubkey(unsigned char *key, unsigned char *blk, int len);

#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_AES_H */
