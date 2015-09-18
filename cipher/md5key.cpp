#define _MD5KEY_CPP

#ifndef _REENTRANT
#define _REENTRANT    /* basic 3-lines for threads */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#ifdef LINUX
#include <sys/time.h>
#endif

#include "md5.h"
#include "md5key.h"

int CalcPasswordLen(int inlen)
{
    return ((inlen+15)/16)*16;
}

int MakePassword(char *output, char *input, int inlen, unsigned char *key, unsigned char *vector)
{
    unsigned int keylen = strlen((char *) key);
    unsigned char buf[128];
    if (keylen > sizeof(buf)-16)
        keylen = sizeof(buf)-16;

    memset(buf, 0, sizeof(buf));
    strncpy((char *) buf, (char *) key, sizeof(buf)-16);
    memcpy(buf+keylen, vector, 16);

    int outlen = ((inlen+15)/16)*16;
    memset(output, 0, outlen);

    outlen = 0;
    int i=0;
    unsigned char b[17], p[17];
    unsigned char *c;
    while (inlen > 0) {
        MD5Calc(buf, keylen + 16, b);
        memset(p, 0, sizeof(p));
        int len = (inlen<16) ? inlen : 16;
        inlen -= len;
        memcpy(p, input+i, len);  //input segment of 16 chars
        c = (unsigned char *) (output+i);    //output buffer

        for (int j=0; j<16; j++)
            buf[keylen+j] = c[j] = p[j] ^ b[j];

        outlen += 16;
        i += len;
    }

    return outlen;
}

/**************************************************
Function:
   unlock the password by MD5 key
***************************************************/
int GetPassword(char *output, char *input, int inlen, unsigned char *key, unsigned char *vector)
{
    unsigned int keylen = strlen((char *) key);
    unsigned char buf[128];
    if (keylen > sizeof(buf)-16)
        keylen = sizeof(buf)-16;

    memset(buf, 0, sizeof(buf));
    strncpy((char *) buf, (char *) key, sizeof(buf)-16);
    memcpy(buf+keylen, vector, 16);

    int outlen = ((inlen+15)/16)*16;
    memset(output, 0, outlen);

    int i=0;
    unsigned char b[17], c[17];
    unsigned char *p;
    outlen = 0;
    while (inlen>0) {
        MD5Calc(buf, keylen + 16, b);
        memset(c, 0, sizeof(c));
        int len = (inlen < 16) ? inlen : 16;
        inlen -= len;
        memcpy(c, input+i, len);  //input segment of 16 chars

        p = (unsigned char *) (output+i);    //output buffer
        for (int j=0; j<16; j++) {
            p[j] = c[j] ^ b[j];
            buf[keylen+j] = c[j];
        }

        outlen += 16;
        i += len;
    }

    return outlen;
}

time_t GetExpireSec(char *expire)
{
    int year;
    int month;
    int day;

    if (sscanf(expire, "%d/%d/%d", &year, &month, &day) != 3) {
        return -1;
    }

    struct tm time_str;
    time_str.tm_year       = year - 1900;
    time_str.tm_mon        = month - 1;
    time_str.tm_mday       = day;
    time_str.tm_hour       = 0;
    time_str.tm_min        = 0;
    time_str.tm_sec        = 1;
    time_str.tm_isdst      = -1;

    time_t expiresec = mktime(&time_str);
    return expiresec;
}

unsigned long GetExpireDays(char *expire)
{
    int year;
    int month;
    int day;

    if (sscanf(expire, "%d/%d/%d", &year, &month, &day) != 3) {
        //printf("error format of expire %s\n", expire);
        return 0;
    }

    //printf("year=%04d, month=%02d, day=%02d\n", year, month, day);
    time_t nowsec;
    time(&nowsec);

    struct tm time_str;
    localtime_r(&nowsec, &time_str);
    time_str.tm_hour       = 0;
    time_str.tm_min        = 0;
    time_str.tm_sec        = 1;
    time_str.tm_isdst      = -1;

    nowsec = mktime(&time_str);
    time_str.tm_year       = year - 1900;
    time_str.tm_mon        = month - 1;
    time_str.tm_mday       = day;
    time_str.tm_hour       = 0;
    time_str.tm_min        = 0;
    time_str.tm_sec        = 1;
    time_str.tm_isdst      = -1;

    time_t expiresec = mktime(&time_str);
    return ((expiresec >= nowsec) ? expiresec - nowsec : 0) / (60*60*24);
}

long ToUINT4(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}

int GenLicenseKey(char *buf,
                  char *product,
                  char *version,
                  char *client,
                  unsigned long users,
                  char *expire,
                  char *hostid )
{
    if (buf == NULL || product == NULL || version == NULL || client == NULL || expire == NULL || hostid == NULL)
        return -1;

    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    unsigned int rs = t.tv_nsec;

    time_t nowsec = t.tv_sec;

    struct tm now_str;
    localtime_r(&nowsec, &now_str);
    now_str.tm_hour = 0;
    now_str.tm_min  = 0;
    now_str.tm_sec  = 1;
    now_str.tm_isdst= -1;

    nowsec = mktime(&now_str);

    unsigned char vector[17];
    memset(vector, 0, sizeof(vector));

    int i;
    for (i = 0; i< 16; i++)
        vector[i] = (unsigned char) rand_r(&rs);

    if (strlen(hostid) != 8)
        return -1;

    long id = 0;
    for (i=0; i<8; i++) {
        id = id*16 + ToUINT4((unsigned char) hostid[i]);
    }

    unsigned char key[10];
    sprintf((char *) key, "%08lx", id);

    char sbuf[1024];
    memset(sbuf, 0, sizeof(sbuf));

    int len = 0;
    memcpy(sbuf+len, vector, 16);
    len += 16;

    int l = strlen(product);
    sbuf[len] = l;
    memcpy(sbuf+len+1, product, l);
    len += l+1;

    l = strlen(version);
    sbuf[len] = l;
    memcpy(sbuf+len+1, version, l);
    len += l+1;

    l = strlen(client);
    sbuf[len] = l;
    memcpy(sbuf+len+1, client, l);
    len += l+1;

    unsigned long v = users;
    unsigned char v1 = (v >> 24) & 0xff;
    unsigned char v2 = (v >> 16) & 0xff;
    unsigned char v3 = (v >> 8) & 0xff;
    unsigned char v4 = v & 0xff;

    sbuf[len] = v1;
    sbuf[len+1] = v2;
    sbuf[len+2] = v3;
    sbuf[len+3] = v4;
    len += 4;

    long expireSec;
    if (strcasecmp(expire, "Never") != 0) {
        expireSec = GetExpireSec(expire);
    }
    else {
        expireSec = -1;
    }

    v = expireSec;
    v1 = (v >> 24) & 0xff;
    v2 = (v >> 16) & 0xff;
    v3 = (v >> 8) & 0xff;
    v4 = v & 0xff;

    sbuf[len] = v1;
    sbuf[len+1] = v2;
    sbuf[len+2] = v3;
    sbuf[len+3] = v4;
    len += 4;

    v = id;
    v1 = (v >> 24) & 0xff;
    v2 = (v >> 16) & 0xff;
    v3 = (v >> 8) & 0xff;
    v4 = v & 0xff;

    sbuf[len] = v1;
    sbuf[len+1] = v2;
    sbuf[len+2] = v3;
    sbuf[len+3] = v4;
    len += 4;

    v = id;
    v1 = (v >> 24) & 0xff;
    v2 = (v >> 16) & 0xff;
    v3 = (v >> 8) & 0xff;
    v4 = v & 0xff;

    buf[0] = v1;
    buf[1] = v2;
    buf[2] = v3;
    buf[3] = v4;

    memcpy(buf+4, vector, 16);
    return MakePassword(buf+20, sbuf, len, key, vector) + 20;
}

LicenseKeyRet CheckLicenseKey(char *key, int keylen,
                              char *product,
                              char *version,
                              char *client,
                              char *hostid,
                              unsigned long *users,
                              long *expire)
{
    if (keylen < 20) {
        printf("CheckLicenseKey() keylen=%d, < 20\n", keylen);
        return kLicenseKeyError;
    }

    if (((keylen-20)%16) != 0) {
        printf("CheckLicenseKey() keylen=%d error\n", keylen);
        return kLicenseKeyError;
    }

    int i;
    long _id=0;
    for (i=0; i<4; i++)
        _id = _id*256 + (unsigned char) key[i];

    char _hostid[9];
    sprintf(_hostid, "%08lx", _id);

    bool hostidOK=false;
    if (strcmp(_hostid, hostid) == 0) {
        hostidOK = true;
    }
    else {
        printf("_hostid=%s, hostid=%s\n", _hostid, hostid);
        hostidOK = false;
    }

    unsigned char md5key[64];
    memset(md5key, 0, sizeof(md5key));
    memcpy(md5key, _hostid, 8);

    unsigned char vector[17];
    memset(vector, 0, sizeof(vector));
    memcpy(vector, key+4, 16);

    char sbuf[1024];
    memset(sbuf, 0, sizeof(sbuf));
    GetPassword(sbuf, key+20, keylen-20, md5key, vector);

    if (memcmp(vector, sbuf, 16) != 0) {
        if (hostidOK) {
            printf("CheckLicenseKey() vector error\n");
            return kLicenseKeyError;
        }
        else
            return kLicenseHostIDError;
    }

    int len = 16;
    int l = (unsigned char) sbuf[len++];

    char _product[64];
    memset(_product, 0, sizeof(_product));
    memcpy(_product, sbuf+len, l);
    len += l;

    l = (unsigned char) sbuf[len++];

    char _version[10];
    memset(_version, 0, sizeof(_version));
    memcpy(_version, sbuf+len, l);
    len += l;

    l = (unsigned char) sbuf[len++];

    char _client[256];
    memset(_client, 0, sizeof(_client));
    memcpy(_client, sbuf+len, l);
    len += l;

    unsigned long _users = 0;
    for (i=0; i<4; i++)
        _users = _users*256 + (unsigned char) sbuf[len++];

    unsigned long _expireSec = 0;
    for (i=0; i<4; i++)
        _expireSec = _expireSec*256 + (unsigned char) sbuf[len++];

    long _id1=0;
    for (i=0; i<4; i++)
        _id1 = _id1*256 + (unsigned char) sbuf[len++];

    //printf("keylen=%d, len=%d\n", keylen, len);
    //struct tm expire_str;
    //localtime_r((time_t *)&_expireSec, &expire_str);

    *users = _users;
    *expire = _expireSec;

    if (_id != _id1) {
        printf("_id=%08x, _id1=%08x\n", _id, _id1);
        hostidOK = false;
    }

    if (strcmp(_product, product) != 0)
        return kLicenseNotThisProduct;

    if (strcmp(_version, version) != 0)
        return kLicenseVersionError;

    if (strcmp(_client, client) != 0)
        return kLicenseClientError;

    time_t nowsec;
    time(&nowsec);

    if ((unsigned long) nowsec >= (unsigned long) _expireSec) {
        printf("now=%d, expire=%u\n", nowsec, _expireSec);
        return kLicenseExpireDayTimeout;
    }

    if (hostidOK == false) {
        printf("_id=%08x, _id1=%08x, hostid=%s\n", _id, _id1, hostid);
        return kLicenseHostIDError;
    }

    return kLicenseOK;
}

#ifdef LINUX
/*Simulate the POSIX.4 time function in Linux,but the precision is microsecond*/
int clock_gettime (int clock_id, struct timespec *ts)
{
    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);
    TIMEVAL_TO_TIMESPEC(&tv, ts);
    return 0;
}
#endif

/*
void main(int argc, char *argv[])
{
    int i, outlen;
    char *key = "88----89";
    char vector[16] = {0x34, 0x5b, 0x0a, 0x9f, 0x1d, 0xfa, 0x27, 0xec, 0x48, 0x35, 0x17, 0xb5, 0x36, 0xd2, 0x6e, 0x4a};
    char secret[16] = {0xb7, 0x52, 0x90, 0x5b, 0xbf, 0xb7, 0x97, 0x6f, 0x19, 0xda, 0xf6, 0xac, 0x1e, 0x9e, 0x9d, 0xe7};
    char output[200], recalc[200];

    if (argc != 2)
        return -1;

    printf("key=%s\n", key);
    printf("input=%s\n", argv[1]);

    outlen = MakePassword(output, argv[1], strlen(argv[1]), key, vector);

    printf("Secret string: ");
    for (i=0; i<outlen; i++)
    printf("[%02x] ", (unsigned char) output[i]);
    printf("\n\tLen=%d\n", outlen);

    printf("other:         ");
    for (i=0; i<16; i++)
        printf("[%02x] ", (unsigned char) secret[i]);
    printf("\n");

    GetPassword(recalc, output, outlen, key, vector);

    printf("recalc=%s\n", recalc);
    return 0;
}
*/
