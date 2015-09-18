#ifndef _USER_RSA_H
#define _USER_RSA_H

#ifdef __cplusplus
extern "C"{
#endif

	void *RSA_Private_Init(const char *cert);

	int RSA_Private_Run(void *key, const void *src, size_t src_len, void *out, size_t *out_len);

	void RSA_Free(void *key);

#ifdef __cplusplus
}
#endif

#endif

