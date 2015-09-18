#ifndef _T_DES_H
#define _T_DES_H

#define MAX_CI_LEN 1024
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */
    int cipher2(const char* key,char* plain_text,char* crypted_text,int length);
    int decipher2(const char* key,char* plain_text,char* crypted_text,int length);
    int cipher3(const char* key,char* plain_text,char* crypted_text,int length);
    int decipher3(const char* key,char* plain_text,char* crypted_text,int length);
    void TDes(char orientation,char *PlainText,char *key, char *ucEncipher);
	char asc_bcd(char *what);
    void tohex(const char* ins, char* outs, int len);
#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif /* _T_DES_H */
