#ifndef _CIPHER_MD5KEY_H_
#define _CIPHER_MD5KEY_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */
int CalcPasswordLen(int inlen);

int MakePassword(char *output, char *input, int inlen, unsigned char *key, unsigned char *vector);
int GetPassword(char *output, char *input, int inlen, unsigned char *key, unsigned char *vector);

enum LicenseKeyRet {
  kLicenseOK = 0,
  kLicenseNotThisProduct = -1,
  kLicenseVersionError = -2,
  kLicenseClientError = -3,
  kLicenseNotEnoughtLicense = -4,
  kLicenseExpireDayError = -5,
  kLicenseExpireDayTimeout = -6,
  kLicenseHostIDError = -7,
  kLicenseKeyError = -8
};

time_t GetExpireSec(char *expire);
unsigned long GetExpireDays(char *expire);
int GenLicenseKey(char *buf, char *product, char *version, char *client, unsigned long users, char *expire, char *hostid);
LicenseKeyRet CheckLicenseKey(char *key, int keylen, char *product, char *version, char *client, char *hostid, unsigned long *users, long *expireSec);

#ifdef __cplusplus
}
#endif /* __cplusplus  */

#endif // _CIPHER_MD5KEY_H_

