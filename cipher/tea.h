
#ifndef _SYS_TEA_H_
#define _SYS_TEA_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */
    /**
     * encrypt plain text to crypt text by TEA alg.
     * @param plain_text
     * @param crypted_text
     * @param len
     * @param iv
     * @param key
     */
  void TeaEncryptCBC(
          unsigned char *crypted_text,
          unsigned char *plain_text,
          int len,
          unsigned char iv[8],
          unsigned char key[16]);

  /**
   * decrypt crypt text to plain text by TEA alg
   * @param plain_text
   * @param crypted_text
   * @param len
   * @param iv
   * @param key
   */
  int TeaDecryptCBC(
          unsigned char *crypted_text,
          unsigned char *plain_text,
          int len,
          unsigned char iv[8],
          unsigned char key[16]);
#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif //_SYS_TEA_H_
