#ifndef _CIPHER_RC4_H
#define _CIPHER_RC4_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */
void RC4_Sample(unsigned char *key, int key_len,
    unsigned char *data, int data_len);
#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif // _CIPHER_RC4_H