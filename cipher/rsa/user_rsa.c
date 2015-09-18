#include <stdio.h>
#include <string.h>
#include "common.h"
#include "base64.h"
#include "rsa.h"
#include "user_rsa.h"


static const u8 * search_tag(const char *tag, const u8 *buf, size_t len)
{
	size_t i, plen;

	plen = os_strlen(tag);
	if (len < plen)
		return NULL;

	for (i = 0; i < len - plen; i++) {
		if (os_memcmp(buf + i, tag, plen) == 0)
			return buf + i;
	}

	return NULL;
}

static u8* get_key(const char *file, const char *start_tag, const char *end_tag, size_t *outlen)
{
	size_t len;
	u8 *buf = os_readfile(file, &len);
	if (!buf)
		return NULL;

	const u8 *pos;
	const u8 *end;
	u8* der;

   	pos = search_tag(start_tag, buf, len);
	if (!pos)
		goto err;

	pos += strlen(start_tag);
	end = search_tag(end_tag, pos, buf + len - pos);
	if (!end)
		goto err;

	der = base64_decode(pos, end-pos, outlen);

	free(buf);
	return der;

err:
	if (buf)
		free(buf);
	return NULL;
}

void *RSA_Private_Init(const char *cert)
{
	size_t l = 0;
	u8* buf = get_key(cert, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", &l);
	if (!buf) {
		fprintf(stderr, "get cert '%s' error\n", cert);
		return NULL;
	}

	void *key = (void *)crypto_rsa_import_private_key(buf, l);
	if (!key) {
		fprintf(stderr, "import private key error\n");
		return NULL;
	}

	os_free(buf);
	return key;
}

int RSA_Private_Run(void *key, const void *src, size_t src_len, void *out, size_t *out_len)
{
	struct crypto_rsa_key *rsa_key = (struct crypto_rsa_key*)key;
	size_t mod_len = crypto_rsa_get_modulus_len(rsa_key);
	if (mod_len < src_len)
		return -1;

	char *p = os_zalloc(mod_len);
	if (!p)
		return -2;
	memcpy(p, src, src_len);
	int ret = crypto_rsa_exptmod(p, mod_len, out, out_len, rsa_key, 1);
	os_free(p);
	return ret;
}

void RSA_Free(void *key)
{
	crypto_rsa_free((struct crypto_rsa_key*)key);
}
