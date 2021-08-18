/*
** Copyright (C) 2014 Wang Yaofu
** All rights reserved.
**
**Author:Wang Yaofu voipman@qq.com
**Description: The unit test file of base64.
*/

#include <string.h>
#include <stdlib.h>
#include "base/base64.h"
#include "cipher/md5.h"
#include "cipher/digest.h"
#include "cipher/sha1.h"
#include "cipher/sha.h"
#include "cipher/sha256.h"
#include "cipher/sha512.h"
#include "cipher/sha224.h"
#include "cipher/sha384.h"
#include "cipher/hmac.h"
#include "cipher/tdes.h"
#include "cipher/rc4.h"
#include "cipher/tea.h"
#include "cipher/pbkdf2_hmac.h"
#include "base/stringutils.h"
#include "ut/test_harness.h"

using namespace std;
using namespace common;
void EncodeAndDecode(const std::string& s)
{
    string b;
    EXPECT_TRUE(Base64Encode(s, &b));

    string c;
    EXPECT_TRUE(Base64Decode(b, &c));
    EXPECT_EQ(c, s);
}

TEST(Base64Test, BasicTest)
{
    EncodeAndDecode("a");
    EncodeAndDecode("ab");
    EncodeAndDecode("abc");
    EncodeAndDecode("abcd");
    EncodeAndDecode("abcde");
    EncodeAndDecode("abcdef");
    EncodeAndDecode("abcdefg");
}

TEST(Base64Test, EncodeEmptyBuffer)
{
    std::string output;
    EXPECT_TRUE(Base64Encode("", &output));
}

TEST(Base64Test, DecodeEmptyString)
{
    std::string output;
    EXPECT_TRUE(Base64Decode("", &output));
}

TEST(Base64Test, DecodeWithPadding)
{
    std::string output;
    std::string s = "e===";
    EXPECT_TRUE(!Base64Decode(s, &output));

    s = "";
    EXPECT_TRUE(Base64Decode(s, &output));

    s = "abcdAFCD\r\neF==";
    EXPECT_TRUE(Base64Decode(s, &output));
    EXPECT_EQ((size_t)7, output.size());

    s = "abcdAFCD\r\neF==\r\n\r\n";
    EXPECT_TRUE(Base64Decode(s, &output));
    EXPECT_EQ((size_t)7, output.size());

    s = "abcdAFCD\r\neF=a";
    EXPECT_TRUE(!Base64Decode(s, &output));

    s = "abcdAFCD\r\ne===";
    EXPECT_TRUE(!Base64Decode(s, &output));

    s = "abcdAFFCD\r\ne==";
    EXPECT_TRUE(Base64Decode(s, &output));
    EXPECT_EQ((size_t)7, output.size());

    s = "abcdAFFCD\r\ne=\r\n=";
    EXPECT_TRUE(Base64Decode(s, &output));
    EXPECT_EQ((size_t)7, output.size());

    s = "abcdAF=D\r\nef==";
    EXPECT_TRUE(!Base64Decode(s, &output));

    s = "abcdA";
    EXPECT_TRUE(!Base64Decode(s, &output));
    Base64Encode("admin:123", &output);
    EXPECT_EQ(string("YWRtaW46MTIz"), output);
    Base64Decode(output, &s);
    EXPECT_EQ(string("admin:123"), s);
}

TEST(Md5Test, BasicTest) {
    unsigned char input[] = "1234567890";
    unsigned char output[100] = {0};
    MD5Calc(input, 10, output);
    std::string cryptOut = "e807f1fcf82d132f9bb018ca6738a19f";
    std::string calcOut = StrUtils::Hex((char *)output, 16);

    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha1Test, BasicTest) {
    unsigned char input[] = "1234567687890";
    unsigned char output[100] = {0};
    //SHA1Calc(input, 13, output);
    SHA_Simple(input, 13, output);
    std::string cryptOut = "21885c92cf31020ba246bfaa999e7c8e508c8d53";
    std::string calcOut = StrUtils::Hex((char *)output, 20);

    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha256Test, BasicTest1)
{

    unsigned char input[] = "abc";
    unsigned char output[33] = {0};
    SHA256_Simple(input, 3, output);
    std::string cryptOut = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    std::string calcOut = StrUtils::Hex((char *)output, 32);
    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha256Test, BasicTest2)
{
    unsigned char input[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char output[65] = {0};
    SHA256_Simple(input, 56, output);
    std::string cryptOut = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    std::string calcOut = StrUtils::Hex((char *)output, 32);
    EXPECT_EQ(cryptOut, calcOut);

}

TEST(Sha224Test, BasicTest1)
{
    unsigned char input[] = "abc";
    unsigned char output[33] = { 0 };
    SHA224_Simple(input, 3, output);
    std::string cryptOut = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    std::string calcOut = StrUtils::Hex((char *)output, 28);
    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha384Test, BasicTest1)
{
    unsigned char input[] = "abc";
    unsigned char output[65] = { 0 };
    SHA384_Simple(input, 3, output);
    std::string cryptOut = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    std::string calcOut = StrUtils::Hex((char *)output, 48);
    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha512Test, BasicTest1)
{
    unsigned char input[] = "abc";
    unsigned char output[65] = {0};
    SHA512_Simple(input, 3, output);
    std::string cryptOut = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    std::string calcOut = StrUtils::Hex((char *)output, 64);
    EXPECT_EQ(cryptOut, calcOut);
}

TEST(Sha512Test, BasicTest2)
{
     unsigned char input[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                             "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
     unsigned char output[65] = {0};
     SHA512_Simple(input, 112, output);
     std::string cryptOut = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
     std::string calcOut = StrUtils::Hex((char *)output, 64);
     EXPECT_EQ(cryptOut, calcOut);
}
TEST(Sha512Test, BasicTest3)
{
    unsigned char input[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char output[65] = {0};
    SHA512_State s;
    int n;
    SHA512_Init(&s);
    for (n = 0; n < 1000000 / 40; n++)
        SHA512_Bytes(&s, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 40);
    SHA512_Final(&s, output);
    std::string cryptOut = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
    std::string calcOut = StrUtils::Hex((char *)output, 64);
    EXPECT_EQ(cryptOut, calcOut);
}

TEST(TdesTest, BasicTest) {
    char key[16]={"key"};
    char encpt[100];
    char result[100];
    char plain[] = "1234567890";
    int len = strlen(plain);
    cipher2(key, plain, encpt, len);
    decipher2(key, result, encpt, strlen(encpt));
    EXPECT_EQ(std::string(plain), std::string(result));

    cipher3(key, plain, encpt,len);
    decipher3(key, result, encpt, strlen(encpt));
    EXPECT_EQ(std::string(plain), std::string(result));
}

TEST(TDigestTest, BasicTest) {
    unsigned char * pszNonce  = (unsigned char*)"xx";
    unsigned char * pszCNonce = (unsigned char*)"248a286a6dda379e";
    unsigned char * pszUser   = (unsigned char*)"admin";
    unsigned char * pszRealm  = (unsigned char*)"xx";
    unsigned char * pszPass   = (unsigned char*)"123456";
    unsigned char * pszAlg    = (unsigned char*)"md5";
    unsigned char * szNonceCount  = (unsigned char*)"00000001";
    unsigned char * pszMethod     = (unsigned char*)"GET";
    unsigned char * pszQop        = (unsigned char*)"auth";
    unsigned char * pszURI        = (unsigned char*)"/fs/v1/addsite";
    HASHHEX HA1;
    HASHHEX HA2 = "";
    HASHHEX Response;

    DigestCalcHA1(pszAlg, pszUser, pszRealm, pszPass, pszNonce, pszCNonce, HA1);
    DigestCalcResponse(HA1, pszNonce, szNonceCount, pszCNonce, pszQop,
        pszMethod, pszURI, HA2, Response);
    string ha1((char *)HA1);
    string digest((char *)Response);
    EXPECT_EQ(string("ec6d21cdfe89d1a6b0be59a8f65a004f"), ha1);
    EXPECT_EQ(string("02233a6d3420e580bf416cd340c43590"), digest);

}

TEST(RC4_Test, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    char blk[100] = {0};
    strcpy(blk, "The quick brown fox jumps over the lazy dog");

    RC4_Sample(key, 3, (unsigned char*)blk, 43);
    string hexBlk = StrUtils::Hex(blk, 43);
    EXPECT_EQ(string("5f0451cd55fa1229236b6a09792a7cdde91b9546c1948e8f45d3c7cb5c9e5bea7c5896e2c8f5c39c57b898"), hexBlk);
    RC4_Sample(key, 3, (unsigned char*)blk, 43);
    EXPECT_EQ(string("The quick brown fox jumps over the lazy dog"), string(blk));
}

TEST(TEA_Test, BasicTest) {
    
    unsigned char plain[] = "my plain";
    unsigned char *key = (unsigned char *) "the secret key...";
    unsigned char *iv = (unsigned char *) "01020304";
    unsigned char crpypt[sizeof(plain) + (8 - (sizeof(plain) % 8))];
    unsigned char decryptPlain[sizeof(plain)];

    TeaEncryptCBC(crpypt, plain, sizeof(m), iv, key);
    unsigned char outs[17] = {0x18,0xd9,0xd8,0x21,0x0a,0x60,0x72,0xe8,0x22,0x19,0x82,0xd2,0x60,0x5f,0xc2,0x22, 0x00};
    EXPECT_EQ(0, memcmp(outs, crpypt, 16));
    
    EXPECT_EQ(0, TeaDecryptCBC(decryptPlain, crpypt, sizeof(crpypt), iv, key));
    EXPECT_EQ(string(decryptPlain), string(plain));
}

TEST(PKCS5_PBKDF2_HMAC_Test, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    char blk[100] = { 0 };
    strcpy(blk, "The quick brown fox jumps over the lazy dog");
    char hmac[21] = { 0 };
    PKCS5_PBKDF2_HMAC((unsigned char*)blk, 43, key, 3, 10, 20, (unsigned char*)hmac);
    string hexBlk = StrUtils::Hex(hmac, 20);
    EXPECT_EQ(string("2ca6b06c1ed5599af0546fc0067d1712e236b1de"), hexBlk);
}

TEST(PKCS5_PBKDF2_HMAC_Test, BasicTest1) {
    unsigned char* key = (unsigned char*)"salt";
    char blk[100] = { 0 };
    strcpy(blk, "password");
    char hmac[21] = { 0 };
    PKCS5_PBKDF2_HMAC((unsigned char*)blk, 8, key, 4, 2, 20, (unsigned char*)hmac);
    string hexBlk = StrUtils::Hex(hmac, 20);
    EXPECT_EQ(string("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"), hexBlk);
}

TEST(PKCS5_PBKDF2_HMAC_Test, BasicTestSha256_1) {
    unsigned char* key = (unsigned char*)"salt";
    char blk[100] = { 0 };
    strcpy(blk, "password");
    char hmac[33] = { 0 };
    PKCS5_PBKDF2_HMAC2((unsigned char*)blk, 8, key, 4, 2, 32, (unsigned char*)hmac);
    string hexBlk = StrUtils::Hex(hmac, 32);
    EXPECT_EQ(string("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"), hexBlk);
}

TEST(PKCS5_PBKDF2_HMAC_Test, BasicTestSha256_2) {
    unsigned char* key = (unsigned char*)"salt";
    char blk[100] = { 0 };
    strcpy(blk, "password");
    char hmac[33] = { 0 };
    PKCS5_PBKDF2_HMAC2((unsigned char*)blk, 8, key, 4, 1, 32, (unsigned char*)hmac);
    string hexBlk = StrUtils::Hex(hmac, 32);
    EXPECT_EQ(string("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), hexBlk);
}


TEST(PKCS5_PBKDF2_HMAC_Test, BasicTestSha512_2) {
    unsigned char* key = (unsigned char*)"salt";
    char blk[100] = { 0 };
    strcpy(blk, "password");
    char hmac[65] = { 0 };
    PKCS5_PBKDF2_HMAC2((unsigned char*)blk, 8, key, 4, 1, 64, (unsigned char*)hmac);
    string hexBlk = StrUtils::Hex(hmac, 64);
    EXPECT_EQ(string("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc18c"), hexBlk);
}

TEST(md5_hmac, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    unsigned char* blk = (unsigned char*)"The quick brown fox jumps over the lazy dog";
    char hmac[21] = {0};

    hmac_md5(key, 3, blk, 43, (unsigned char*)hmac);
    string actualHmac = StrUtils::Hex(hmac, 16);
    EXPECT_EQ(string("80070713463e7749b90c2dc24911e275"), actualHmac);

    memset(hmac, 0, sizeof hmac);
    hmac_md5(key, 0, blk, 0, (unsigned char*)hmac);
    actualHmac = StrUtils::Hex(hmac, 16);
    EXPECT_EQ(string("74e6f7298a9c2d168935f58c001bad88"), actualHmac);

}

TEST(sha1_hmac, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    unsigned char* blk = (unsigned char*)"wangyaofu try sha256 hash.";
    char hmac[21] = { 0 };

    hmac_sha1(key, 3, blk, 26, (unsigned char*)hmac);
    string actualHmac = StrUtils::Hex(hmac, 20);
    EXPECT_EQ(string("5e3c90f7bcbbe8c4ae878d7a6b186c112f005714"), actualHmac);

    memset(hmac, 0, sizeof hmac);
    hmac_sha1(key, 0, blk, 26, (unsigned char*)hmac);
    actualHmac = StrUtils::Hex(hmac, 20);
    EXPECT_EQ(string("df50dee5e03d275d9fcfc024893e1dc94e464a8c"), actualHmac);

}

TEST(sha224_hmac, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    unsigned char* blk = (unsigned char*)"wangyaofu try sha224 hash.";
    char hmac[33] = { 0 };

    hmac_sha224(key, 3, blk, 26, (unsigned char*)hmac);
    string actualHmac = StrUtils::Hex(hmac, 28);
    EXPECT_EQ(string("4d5a9a6ed549145dfbc30b0752ae3e05e06ccdd5695ec980f5a5739e"), actualHmac);

    memset(hmac, 0, sizeof hmac);
    hmac_sha224(key, 0, blk, 26, (unsigned char*)hmac);
    actualHmac = StrUtils::Hex(hmac, 28);
    EXPECT_EQ(string("91a5e2e9d550a8bdd82c1e59bb149655fc6d34d90d8a29ce77a391d2"), actualHmac);
}

TEST(sha256_hmac, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    unsigned char* blk = (unsigned char*)"wangyaofu try sha256 hash.";
    char hmac[33] = { 0 };

    hmac_sha256(key, 3, blk, 26, (unsigned char*)hmac);
    string actualHmac = StrUtils::Hex(hmac, 32);
    EXPECT_EQ(string("dc1099cd35452f3cf1f6c11d3884bc4c9b637523c4e74060e1332eac01e7ad8e"), actualHmac);

    memset(hmac, 0, sizeof hmac);
    hmac_sha256(key, 0, blk, 26, (unsigned char*)hmac);
    actualHmac = StrUtils::Hex(hmac, 32);
    EXPECT_EQ(string("37df81f1f26bb3949d4aad5ee27bb8bc5f124a7ff4d46e6d572ed96d5bde0ed8"), actualHmac);
}

TEST(sha512_hmac, BasicTest) {
    unsigned char* key = (unsigned char*)"key";
    unsigned char* blk = (unsigned char*)"37df81f1f26bb3949d4aad5ee27bb8bc5f124a7ff4d46e6d572ed96d5bde0ed8";
    char hmac[65] = { 0 };

    hmac_sha512(key, 3, blk, 64, (unsigned char*)hmac);
    string actualHmac = StrUtils::Hex(hmac, 64);
    EXPECT_EQ(string("f671db32ad7cc79121e432bd05f2e1a3ecf2f450c73b839584feb0371a4c05d018222a59fea6077e3681dc27322e1f389a35118f0e23188d7d4ca10741ee7746"), actualHmac);

    memset(hmac, 0, sizeof hmac);
    hmac_sha512(key, 0, blk, 64, (unsigned char*)hmac);
    actualHmac = StrUtils::Hex(hmac, 64);
    EXPECT_EQ(string("ac7b05b5c77842d7d8697bd0bb19ee74952f291b5dff9b2a2e58d82192368576dc81277ab3d59c0bc5a8fec61470ca1d8e3766f873d9769290be7c4cc855f32f"), actualHmac);
}
