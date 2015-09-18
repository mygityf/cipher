#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "common.h"
#include "base64.h"
#include "rsa.h"

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

u8* get_key(const char *file, const char *start_tag, const char *end_tag, size_t *outlen)
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

	//prt(der, *outlen);


	free(buf);
	return der;

err:
	if (buf)
		free(buf);
	return NULL;
}


static void prt(void *p, int len)
{
	int i;
	char *d = (char *)p;
	for (i = 0; i < len; ++i) {
		printf("%02x ", (unsigned char)d[i]);
		if (i != 0 && (i+1)%20 == 0)
			printf("\n");
	}
	printf("\n");
}


int main(int argc, char *argv[])
{
	extern int wpa_debug_level;
	wpa_debug_level = MSG_MSGDUMP;
	struct crypto_rsa_key *key = NULL;
	u8* buf = NULL;;
	size_t l = 0;

	if (argc > 1) {
		buf = get_key("./pubkey", "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", &l);
		if (!buf)
			return 0;

		key = crypto_rsa_import_public_key(buf, l);
		if (!key) {
			printf("private error\n");
			goto err;
		}

		char src[1024];
		memset(src, 0, sizeof(src));
		strcpy(src, argv[1]);
		int mod_len = crypto_rsa_get_modulus_len(key);
		printf("modulus len=%d\n", mod_len);

		char encrypt_buf[1024];
		memset(encrypt_buf, 0, sizeof(encrypt_buf));
		size_t buf_len = sizeof(encrypt_buf);
		if (0 == crypto_rsa_exptmod(src, mod_len, encrypt_buf, &buf_len, key, 0)) {
			printf("result len=%d\n", buf_len);
			prt(encrypt_buf, buf_len);

			FILE *fp=fopen("out.bin", "w");
			if (fp) {
				fwrite(encrypt_buf, 1, buf_len, fp);
			}
			fclose(fp);
		}
	} else {
		buf = get_key("./privkey", "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", &l);
		if (!buf)
			return 0;

		key = crypto_rsa_import_private_key(buf, l);
		if (!key) {
			printf("public error\n");
			goto err;
		}

		size_t f_len;
		char *p = os_readfile("out.bin", &f_len);
		if (p) {
			char decrypt_buf[1024];
			memset(decrypt_buf, 0, sizeof(decrypt_buf));
			size_t buf_len = sizeof(decrypt_buf);

			if (0 == crypto_rsa_exptmod(p, f_len, decrypt_buf, &buf_len, key, 1)) {
				printf("outlen = %d\n", buf_len);
				prt(decrypt_buf, buf_len);
			}
			free(p);
		}
	}

err:
	free(buf);
	crypto_rsa_free(key);
}
