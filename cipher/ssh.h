#ifndef _CIPHER_SSHSSH_H_
#define _CIPHER_SSHSSH_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */
    struct ssh_mac {
        void *(*make_context)(void);
        void (*free_context)(void *);
        void (*setkey) (void *, unsigned char *key);
        /* whole-packet operations */
        void (*generate) (void *, unsigned char *blk, int len, unsigned long seq);
        int (*verify) (void *, unsigned char *blk, int len, unsigned long seq);
        /* partial-packet operations */
        void (*start) (void *);
        void (*bytes) (void *, unsigned char *, int);
        void (*genresult) (void *, unsigned char *);
        int (*verresult) (void *, unsigned char *);
        char *name;
        int len;
        char *text_name;
    };
    
    struct ssh_hash {
        void *(*init)(void); /* also allocates context */
        void (*bytes)(void *, void *, int);
        void (*final)(void *, unsigned char *); /* also frees context */
        int hlen; /* output length in bytes */
        char *text_name;
    };
    struct ssh2_cipher {
        void *(*make_context)(void);
        void (*free_context)(void *);
        void (*setiv) (void *, unsigned char *key);	/* for SSH-2 */
        void (*setkey) (void *, unsigned char *key);/* for SSH-2 */
        void (*encrypt) (void *, unsigned char *blk, int len);
        void (*decrypt) (void *, unsigned char *blk, int len);
        char *name;
        int blksize;
        int keylen;
        unsigned int flags;
    #define SSH_CIPHER_IS_CBC	1
        char *text_name;
    };
    extern const struct ssh_mac ssh_hmac_md5;
    extern const struct ssh_mac ssh_hmac_sha1;
    extern const struct ssh_mac ssh_hmac_sha1_buggy;
    extern const struct ssh_mac ssh_hmac_sha1_96;
    extern const struct ssh_mac ssh_hmac_sha1_96_buggy;
    extern const struct ssh_mac ssh_hmac_sha256;

#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif /* _CIPHER_SSHSSH_H_ */
