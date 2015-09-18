#ifndef _CIPHER_DIGEST_H_
#define _CIPHER_DIGEST_H_

/* from rfc2617 */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */

#define HASHLEN 16
typedef unsigned char HASH[HASHLEN];
#define HASHHEXLEN 32
typedef unsigned char HASHHEX[HASHHEXLEN+1];
#define IN
#define OUT

/* calculate H(A1) as per HTTP Digest spec */
void DigestCalcHA1(
    IN unsigned char * pszAlg,
    IN unsigned char * pszUserName,
    IN unsigned char * pszRealm,
    IN unsigned char * pszPassword,
    IN unsigned char * pszNonce,
    IN unsigned char * pszCNonce,
    OUT HASHHEX SessionKey
    );

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(
    IN HASHHEX HA1,           /* H(A1) */
    IN unsigned char * pszNonce,       /* nonce from server */
    IN unsigned char * pszNonceCount,  /* 8 hex digits */
    IN unsigned char * pszCNonce,      /* client nonce */
    IN unsigned char * pszQop,         /* qop-value: "", "auth", "auth-int" */
    IN unsigned char * pszMethod,      /* method from the request */
    IN unsigned char * pszDigestUri,   /* requested URL */
    IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
    OUT HASHHEX Response      /* request-digest or response-digest */
    );

#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif /* _CIPHER_DIGEST_H_ */