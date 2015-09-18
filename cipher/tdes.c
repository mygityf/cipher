#include <stdio.h>
#include <string.h>
#include "tdes.h"
#define MAX_CI_LEN 1024
#ifndef LINUX
struct byte
{
    unsigned bit7:1;
    unsigned bit6:1;
    unsigned bit5:1;
    unsigned bit4:1;
    unsigned bit3:1;
    unsigned bit2:1;
    unsigned bit1:1;
    unsigned bit0:1;
};
#else
struct byte
{
    unsigned bit0:1;
    unsigned bit1:1;
    unsigned bit2:1;
    unsigned bit3:1;
    unsigned bit4:1;
    unsigned bit5:1;
    unsigned bit6:1;
    unsigned bit7:1;
};
#endif
union hbyte
{
    struct byte ibyte;
    unsigned char abyte;
};

char triple_des_key[16]={0x44,0x2f,0x7c,0xda,0x9c,0xb0,0x98,0xe8,
0x8f,0xc5,0xd4,0xfd,0x32,0x79,0x24,0x12};

/*-----------------------------------------------------------
DES Expand procedure
Description: Expand 32 bits to 48 bits
-----------------------------------------------------------*/
void expand(char in[4], char out[6])
{
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    ip1.abyte=in[0];  ipr.ibyte.bit7=ip1.ibyte.bit0;  /* bit 32 */
    ip1.abyte=in[3];  ipr.ibyte.bit6=ip1.ibyte.bit7;  /* bit 1 */
    ip1.abyte=in[3];  ipr.ibyte.bit5=ip1.ibyte.bit6;  /* bit 2 */
    ip1.abyte=in[3];  ipr.ibyte.bit4=ip1.ibyte.bit5;  /* bit 3 */
    ip1.abyte=in[3];  ipr.ibyte.bit3=ip1.ibyte.bit4;  /* bit 4 */
    ip1.abyte=in[3];  ipr.ibyte.bit2=ip1.ibyte.bit3;  /* bit 5 */
    ip1.abyte=in[3];  ipr.ibyte.bit1=ip1.ibyte.bit4;  /* bit 4 */
    ip1.abyte=in[3];  ipr.ibyte.bit0=ip1.ibyte.bit3;  /* bit 5 */
    out[5]=ipr.abyte;

    ip1.abyte=in[3];  ipr.ibyte.bit7=ip1.ibyte.bit2;  /* bit 6  */
    ip1.abyte=in[3];  ipr.ibyte.bit6=ip1.ibyte.bit1;  /* bit 7  */
    ip1.abyte=in[3];  ipr.ibyte.bit5=ip1.ibyte.bit0;  /* bit 8  */
    ip1.abyte=in[2];  ipr.ibyte.bit4=ip1.ibyte.bit7;  /* bit 9  */
    ip1.abyte=in[3];  ipr.ibyte.bit3=ip1.ibyte.bit0;  /* bit 8  */
    ip1.abyte=in[2];  ipr.ibyte.bit2=ip1.ibyte.bit7;  /* bit 9  */
    ip1.abyte=in[2];  ipr.ibyte.bit1=ip1.ibyte.bit6;  /* bit 10  */
    ip1.abyte=in[2];  ipr.ibyte.bit0=ip1.ibyte.bit5;  /* bit 11  */
    out[4]=ipr.abyte;

    ip1.abyte=in[2];  ipr.ibyte.bit7=ip1.ibyte.bit4;  /* bit 12  */
    ip1.abyte=in[2];  ipr.ibyte.bit6=ip1.ibyte.bit3;  /* bit 13  */
    ip1.abyte=in[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;  /* bit 12  */
    ip1.abyte=in[2];  ipr.ibyte.bit4=ip1.ibyte.bit3;  /* bit 13  */
    ip1.abyte=in[2];  ipr.ibyte.bit3=ip1.ibyte.bit2;  /* bit 14  */
    ip1.abyte=in[2];  ipr.ibyte.bit2=ip1.ibyte.bit1;  /* bit 15  */
    ip1.abyte=in[2];  ipr.ibyte.bit1=ip1.ibyte.bit0;  /* bit 16  */
    ip1.abyte=in[1];  ipr.ibyte.bit0=ip1.ibyte.bit7;  /* bit 17  */
    out[3]=ipr.abyte;

    ip1.abyte=in[2];  ipr.ibyte.bit7=ip1.ibyte.bit0;  /* bit 16 */
    ip1.abyte=in[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;  /* bit 17 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit6;  /* bit 18  */
    ip1.abyte=in[1];  ipr.ibyte.bit4=ip1.ibyte.bit5;  /* bit 19  */
    ip1.abyte=in[1];  ipr.ibyte.bit3=ip1.ibyte.bit4;  /* bit 20  */
    ip1.abyte=in[1];  ipr.ibyte.bit2=ip1.ibyte.bit3;  /* bit 21  */
    ip1.abyte=in[1];  ipr.ibyte.bit1=ip1.ibyte.bit4;  /* bit 20  */
    ip1.abyte=in[1];  ipr.ibyte.bit0=ip1.ibyte.bit3;  /* bit 21  */
    out[2]=ipr.abyte;

    ip1.abyte=in[1];  ipr.ibyte.bit7=ip1.ibyte.bit2;  /* bit 22 */
    ip1.abyte=in[1];  ipr.ibyte.bit6=ip1.ibyte.bit1;  /* bit 23 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit0;  /* bit 24 */
    ip1.abyte=in[0];  ipr.ibyte.bit4=ip1.ibyte.bit7;  /* bit 25 */
    ip1.abyte=in[1];  ipr.ibyte.bit3=ip1.ibyte.bit0;  /* bit 24 */
    ip1.abyte=in[0];  ipr.ibyte.bit2=ip1.ibyte.bit7;  /* bit 25 */
    ip1.abyte=in[0];  ipr.ibyte.bit1=ip1.ibyte.bit6;  /* bit 26 */
    ip1.abyte=in[0];  ipr.ibyte.bit0=ip1.ibyte.bit5;  /* bit 27 */
    out[1]=ipr.abyte;

    ip1.abyte=in[0];  ipr.ibyte.bit7=ip1.ibyte.bit4;  /* bit 28 */
    ip1.abyte=in[0];  ipr.ibyte.bit6=ip1.ibyte.bit3;  /* bit 29 */
    ip1.abyte=in[0];  ipr.ibyte.bit5=ip1.ibyte.bit4;  /* bit 28 */
    ip1.abyte=in[0];  ipr.ibyte.bit4=ip1.ibyte.bit3;  /* bit 29 */
    ip1.abyte=in[0];  ipr.ibyte.bit3=ip1.ibyte.bit2;  /* bit 30 */
    ip1.abyte=in[0];  ipr.ibyte.bit2=ip1.ibyte.bit1;  /* bit 31 */
    ip1.abyte=in[0];  ipr.ibyte.bit1=ip1.ibyte.bit0;  /* bit 32 */
    ip1.abyte=in[3];  ipr.ibyte.bit0=ip1.ibyte.bit7;  /* bit 1 */
    out[0]=ipr.abyte;

    return;
}

/*-----------------------------------------------------------
DES Compress procedure
Description:
-----------------------------------------------------------*/
static void compress(char in[6],char out[4])
{
    /* S Box */
    char s[8][4][16]={
        /* S1 */
        14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
        0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
        4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
        15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13,
        /* S2 */
        15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
        3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
        0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
        13,8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9,
        /* S3 */
        10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
        13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
        1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12,
        /* S4 */
        7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
        13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
        10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
        3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14,
        /* S5 */
        2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
        14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
        4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
        11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3,
        /* S6 */
        12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
        10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
        9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
        4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13,
        /* S7 */
        4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
        13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
        1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
        6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12,
        /* S8 */
        13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
        1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
        7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
        2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11
    };

    union hbyte ip1;
    union hbyte ipr;
    char tmp[8];
    char c[8];
    int i;
    char hang,lie;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Trans 6 bytes to 8 bytes of 6 bits */
    ip1.abyte=in[5];  ipr.ibyte.bit7=ip1.ibyte.bit7;  /* bit 1 */
    ip1.abyte=in[5];  ipr.ibyte.bit6=ip1.ibyte.bit6;  /* bit 2 */
    ip1.abyte=in[5];  ipr.ibyte.bit5=ip1.ibyte.bit5;  /* bit 3 */
    ip1.abyte=in[5];  ipr.ibyte.bit4=ip1.ibyte.bit4;  /* bit 4 */
    ip1.abyte=in[5];  ipr.ibyte.bit3=ip1.ibyte.bit3;  /* bit 5 */
    ip1.abyte=in[5];  ipr.ibyte.bit2=ip1.ibyte.bit2;  /* bit 6 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[7]=ipr.abyte;

    ip1.abyte=in[5];  ipr.ibyte.bit7=ip1.ibyte.bit1;  /* bit 7 */
    ip1.abyte=in[5];  ipr.ibyte.bit6=ip1.ibyte.bit0;  /* bit 8 */
    ip1.abyte=in[4];  ipr.ibyte.bit5=ip1.ibyte.bit7;  /* bit 9 */
    ip1.abyte=in[4];  ipr.ibyte.bit4=ip1.ibyte.bit6;  /* bit 10 */
    ip1.abyte=in[4];  ipr.ibyte.bit3=ip1.ibyte.bit5;  /* bit 11 */
    ip1.abyte=in[4];  ipr.ibyte.bit2=ip1.ibyte.bit4;  /* bit 12 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[6]=ipr.abyte;

    ip1.abyte=in[4];  ipr.ibyte.bit7=ip1.ibyte.bit3;  /* bit 13 */
    ip1.abyte=in[4];  ipr.ibyte.bit6=ip1.ibyte.bit2;  /* bit 14 */
    ip1.abyte=in[4];  ipr.ibyte.bit5=ip1.ibyte.bit1;  /* bit 15 */
    ip1.abyte=in[4];  ipr.ibyte.bit4=ip1.ibyte.bit0;  /* bit 16 */
    ip1.abyte=in[3];  ipr.ibyte.bit3=ip1.ibyte.bit7;  /* bit 17 */
    ip1.abyte=in[3];  ipr.ibyte.bit2=ip1.ibyte.bit6;  /* bit 18 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[5]=ipr.abyte;

    ip1.abyte=in[3];  ipr.ibyte.bit7=ip1.ibyte.bit5;  /* bit 19 */
    ip1.abyte=in[3];  ipr.ibyte.bit6=ip1.ibyte.bit4;  /* bit 20 */
    ip1.abyte=in[3];  ipr.ibyte.bit5=ip1.ibyte.bit3;  /* bit 21 */
    ip1.abyte=in[3];  ipr.ibyte.bit4=ip1.ibyte.bit2;  /* bit 22 */
    ip1.abyte=in[3];  ipr.ibyte.bit3=ip1.ibyte.bit1;  /* bit 23 */
    ip1.abyte=in[3];  ipr.ibyte.bit2=ip1.ibyte.bit0;  /* bit 24 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[4]=ipr.abyte;

    ip1.abyte=in[2];  ipr.ibyte.bit7=ip1.ibyte.bit7;  /* bit 25 */
    ip1.abyte=in[2];  ipr.ibyte.bit6=ip1.ibyte.bit6;  /* bit 26 */
    ip1.abyte=in[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;  /* bit 27 */
    ip1.abyte=in[2];  ipr.ibyte.bit4=ip1.ibyte.bit4;  /* bit 28 */
    ip1.abyte=in[2];  ipr.ibyte.bit3=ip1.ibyte.bit3;  /* bit 29 */
    ip1.abyte=in[2];  ipr.ibyte.bit2=ip1.ibyte.bit2;  /* bit 30 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[3]=ipr.abyte;

    ip1.abyte=in[2];  ipr.ibyte.bit7=ip1.ibyte.bit1;  /* bit 31 */
    ip1.abyte=in[2];  ipr.ibyte.bit6=ip1.ibyte.bit0;  /* bit 32 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit7;  /* bit 33 */
    ip1.abyte=in[1];  ipr.ibyte.bit4=ip1.ibyte.bit6;  /* bit 34 */
    ip1.abyte=in[1];  ipr.ibyte.bit3=ip1.ibyte.bit5;  /* bit 35 */
    ip1.abyte=in[1];  ipr.ibyte.bit2=ip1.ibyte.bit4;  /* bit 36 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[2]=ipr.abyte;

    ip1.abyte=in[1];  ipr.ibyte.bit7=ip1.ibyte.bit3;  /* bit 37 */
    ip1.abyte=in[1];  ipr.ibyte.bit6=ip1.ibyte.bit2;  /* bit 38 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit1;  /* bit 39 */
    ip1.abyte=in[1];  ipr.ibyte.bit4=ip1.ibyte.bit0;  /* bit 40 */
    ip1.abyte=in[0];  ipr.ibyte.bit3=ip1.ibyte.bit7;  /* bit 41 */
    ip1.abyte=in[0];  ipr.ibyte.bit2=ip1.ibyte.bit6;  /* bit 42 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[1]=ipr.abyte;

    ip1.abyte=in[0];  ipr.ibyte.bit7=ip1.ibyte.bit5;  /* bit 43 */
    ip1.abyte=in[0];  ipr.ibyte.bit6=ip1.ibyte.bit4;  /* bit 44 */
    ip1.abyte=in[0];  ipr.ibyte.bit5=ip1.ibyte.bit3;  /* bit 45 */
    ip1.abyte=in[0];  ipr.ibyte.bit4=ip1.ibyte.bit2;  /* bit 46 */
    ip1.abyte=in[0];  ipr.ibyte.bit3=ip1.ibyte.bit1;  /* bit 47 */
    ip1.abyte=in[0];  ipr.ibyte.bit2=ip1.ibyte.bit0;  /* bit 48 */
    ipr.ibyte.bit1=0;               /* bit  */
    ipr.ibyte.bit0=0;               /* bit  */
    tmp[0]=ipr.abyte;

    /* Compress 6 bits to 4 bits */
    i=7;
    while (i>=0) {
        ip1.abyte=tmp[i];
        ipr.ibyte.bit1=ip1.ibyte.bit7;  /* Hang Number */
        ipr.ibyte.bit0=ip1.ibyte.bit2;
        hang=ipr.abyte & 0x03;

        ipr.ibyte.bit3=ip1.ibyte.bit6;  /* Lie Number */
        ipr.ibyte.bit2=ip1.ibyte.bit5;
        ipr.ibyte.bit1=ip1.ibyte.bit4;
        ipr.ibyte.bit0=ip1.ibyte.bit3;
        lie=ipr.abyte & 0x0F;

        c[i]=s[7-i][hang][lie];
        i=i-1;
    }

    out[3]=(c[7]<<4)|c[6];
    out[2]=(c[5]<<4)|c[4];
    out[1]=(c[3]<<4)|c[2];
    out[0]=(c[1]<<4)|c[0];

    return;
}

/*-----------------------------------------------------------
DES Permutation procedure
Description:
-----------------------------------------------------------*/
void permutate(char in[4],char out[4])
{
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Trans Array Out[4] */
    ip1.abyte=in[2];  ipr.ibyte.bit7=ip1.ibyte.bit0;  /* bit 16 */
    ip1.abyte=in[3];  ipr.ibyte.bit6=ip1.ibyte.bit1;  /* bit 7 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit4;  /* bit 20 */
    ip1.abyte=in[1];  ipr.ibyte.bit4=ip1.ibyte.bit3;  /* bit 21 */
    ip1.abyte=in[0];  ipr.ibyte.bit3=ip1.ibyte.bit3;  /* bit 29 */
    ip1.abyte=in[2];  ipr.ibyte.bit2=ip1.ibyte.bit4;  /* bit 12 */
    ip1.abyte=in[0];  ipr.ibyte.bit1=ip1.ibyte.bit4;  /* bit 28 */
    ip1.abyte=in[1];  ipr.ibyte.bit0=ip1.ibyte.bit7;  /* bit 17 */
    out[3]=ipr.abyte;

    ip1.abyte=in[3];  ipr.ibyte.bit7=ip1.ibyte.bit7;  /* bit 1 */
    ip1.abyte=in[2];  ipr.ibyte.bit6=ip1.ibyte.bit1;  /* bit 15 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit1;  /* bit 23 */
    ip1.abyte=in[0];  ipr.ibyte.bit4=ip1.ibyte.bit6;  /* bit 26 */
    ip1.abyte=in[3];  ipr.ibyte.bit3=ip1.ibyte.bit3;  /* bit 5 */
    ip1.abyte=in[1];  ipr.ibyte.bit2=ip1.ibyte.bit6;  /* bit 18 */
    ip1.abyte=in[0];  ipr.ibyte.bit1=ip1.ibyte.bit1;  /* bit 31 */
    ip1.abyte=in[2];  ipr.ibyte.bit0=ip1.ibyte.bit6;  /* bit 10 */
    out[2]=ipr.abyte;

    ip1.abyte=in[3];  ipr.ibyte.bit7=ip1.ibyte.bit6;  /* bit 2 */
    ip1.abyte=in[3];  ipr.ibyte.bit6=ip1.ibyte.bit0;  /* bit 8 */
    ip1.abyte=in[1];  ipr.ibyte.bit5=ip1.ibyte.bit0;  /* bit 24 */
    ip1.abyte=in[2];  ipr.ibyte.bit4=ip1.ibyte.bit2;  /* bit 14 */
    ip1.abyte=in[0];  ipr.ibyte.bit3=ip1.ibyte.bit0;  /* bit 32 */
    ip1.abyte=in[0];  ipr.ibyte.bit2=ip1.ibyte.bit5;  /* bit 27 */
    ip1.abyte=in[3];  ipr.ibyte.bit1=ip1.ibyte.bit5;  /* bit 3 */
    ip1.abyte=in[2];  ipr.ibyte.bit0=ip1.ibyte.bit7;  /* bit 9 */
    out[1]=ipr.abyte;

    ip1.abyte=in[1];  ipr.ibyte.bit7=ip1.ibyte.bit5;  /* bit 19 */
    ip1.abyte=in[2];  ipr.ibyte.bit6=ip1.ibyte.bit3;  /* bit 13 */
    ip1.abyte=in[0];  ipr.ibyte.bit5=ip1.ibyte.bit2;  /* bit 30 */
    ip1.abyte=in[3];  ipr.ibyte.bit4=ip1.ibyte.bit2;  /* bit 6 */
    ip1.abyte=in[1];  ipr.ibyte.bit3=ip1.ibyte.bit2;  /* bit 22 */
    ip1.abyte=in[2];  ipr.ibyte.bit2=ip1.ibyte.bit5;  /* bit 11 */
    ip1.abyte=in[3];  ipr.ibyte.bit1=ip1.ibyte.bit4;  /* bit 4 */
    ip1.abyte=in[0];  ipr.ibyte.bit0=ip1.ibyte.bit7;  /* bit 25 */
    out[0]=ipr.abyte;

    return;
}

/*-----------------------------------------------------------
PC-2
Description: Sub Procedure of Subkey
-----------------------------------------------------------*/
void pc2(char keyc[4],char keyd[4],char subkey[6])
{
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Trans Ci */
    ip1.abyte=keyc[2];  ipr.ibyte.bit7=ip1.ibyte.bit2;  /* bit 14 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;  /* bit 17 */
    ip1.abyte=keyc[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;  /* bit 11 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit4=ip1.ibyte.bit0;  /* bit 24 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit3=ip1.ibyte.bit7;  /* bit 1 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit2=ip1.ibyte.bit3;  /* bit 5 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit1=ip1.ibyte.bit5;  /* bit 3 */
    ip1.abyte=keyc[0];  ipr.ibyte.bit0=ip1.ibyte.bit4;  /* bit 28 */
    subkey[5]=ipr.abyte;

    ip1.abyte=keyc[2];  ipr.ibyte.bit7=ip1.ibyte.bit1;  /* bit 15 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit6=ip1.ibyte.bit2;  /* bit 6 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit5=ip1.ibyte.bit3;  /* bit 21 */
    ip1.abyte=keyc[2];  ipr.ibyte.bit4=ip1.ibyte.bit6;  /* bit 10 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit3=ip1.ibyte.bit1;  /* bit 23 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit2=ip1.ibyte.bit5;  /* bit 19 */
    ip1.abyte=keyc[2];  ipr.ibyte.bit1=ip1.ibyte.bit4;  /* bit 12 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit0=ip1.ibyte.bit4;  /* bit 4 */
    subkey[4]=ipr.abyte;

    ip1.abyte=keyc[0];  ipr.ibyte.bit7=ip1.ibyte.bit6;  /* bit 26 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit6=ip1.ibyte.bit0;  /* bit 8 */
    ip1.abyte=keyc[2];  ipr.ibyte.bit5=ip1.ibyte.bit0;  /* bit 16 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit4=ip1.ibyte.bit1;  /* bit 7 */
    ip1.abyte=keyc[0];  ipr.ibyte.bit3=ip1.ibyte.bit5;  /* bit 27 */
    ip1.abyte=keyc[1];  ipr.ibyte.bit2=ip1.ibyte.bit4;  /* bit 20 */
    ip1.abyte=keyc[2];  ipr.ibyte.bit1=ip1.ibyte.bit3;  /* bit 13 */
    ip1.abyte=keyc[3];  ipr.ibyte.bit0=ip1.ibyte.bit6;  /* bit 2 */
    subkey[3]=ipr.abyte;

    /* Trans Di */
    ip1.abyte=keyd[2];  ipr.ibyte.bit7=ip1.ibyte.bit3;  /* bit 41 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit6=ip1.ibyte.bit0;  /* bit 52 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit5=ip1.ibyte.bit5;  /* bit 31 */
    ip1.abyte=keyd[2];  ipr.ibyte.bit4=ip1.ibyte.bit7;  /* bit 37 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit3=ip1.ibyte.bit5;  /* bit 47 */
    ip1.abyte=keyd[0];  ipr.ibyte.bit2=ip1.ibyte.bit5;  /* bit 55 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit1=ip1.ibyte.bit6;  /* bit 30 */
    ip1.abyte=keyd[2];  ipr.ibyte.bit0=ip1.ibyte.bit4;  /* bit 40 */
    subkey[2]=ipr.abyte;

    ip1.abyte=keyd[1];  ipr.ibyte.bit7=ip1.ibyte.bit1;  /* bit 51 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;  /* bit 45 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit5=ip1.ibyte.bit3;  /* bit 33 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit4=ip1.ibyte.bit4;  /* bit 48 */
    ip1.abyte=keyd[2];  ipr.ibyte.bit3=ip1.ibyte.bit0;  /* bit 44 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit2=ip1.ibyte.bit3;  /* bit 49 */
    ip1.abyte=keyd[2];  ipr.ibyte.bit1=ip1.ibyte.bit5;  /* bit 39 */
    ip1.abyte=keyd[0];  ipr.ibyte.bit0=ip1.ibyte.bit4;  /* bit 56 */
    subkey[1]=ipr.abyte;

    ip1.abyte=keyd[3];  ipr.ibyte.bit7=ip1.ibyte.bit2;  /* bit 34 */
    ip1.abyte=keyd[0];  ipr.ibyte.bit6=ip1.ibyte.bit7;  /* bit 53 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit5=ip1.ibyte.bit6;  /* bit 46 */
    ip1.abyte=keyd[2];  ipr.ibyte.bit4=ip1.ibyte.bit2;  /* bit 42 */
    ip1.abyte=keyd[1];  ipr.ibyte.bit3=ip1.ibyte.bit2;  /* bit 50 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit2=ip1.ibyte.bit0;  /* bit 36 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit1=ip1.ibyte.bit7;  /* bit 29 */
    ip1.abyte=keyd[3];  ipr.ibyte.bit0=ip1.ibyte.bit4;  /* bit 32 */
    subkey[0]=ipr.abyte;

    return;
}

/*-----------------------------------------------------------
Rotate bits
Description: Sub Procedure of Subkey
-----------------------------------------------------------*/
void rotatebits(char key[4],char skey[4],char bits)
{
    union hbyte c[4],d[4];

    c[0].abyte=key[0];
    c[1].abyte=key[1];
    c[2].abyte=key[2];
    c[3].abyte=key[3];

    /* total 28 bits */
    if (bits==1){
        /* Key[0] */
        d[0].ibyte.bit4=c[3].ibyte.bit7;    /* bit 1 */

        d[0].ibyte.bit5=c[0].ibyte.bit4;    /* bit 2 */
        d[0].ibyte.bit6=c[0].ibyte.bit5;    /* bit 3 */
        d[0].ibyte.bit7=c[0].ibyte.bit6;    /* bit 4 */

        /* key[1] */
        d[1].ibyte.bit0=c[0].ibyte.bit7;    /* bit 5 */
        d[1].ibyte.bit1=c[1].ibyte.bit0;    /* bit 6 */
        d[1].ibyte.bit2=c[1].ibyte.bit1;    /* bit 7 */
        d[1].ibyte.bit3=c[1].ibyte.bit2;    /* bit 8 */
        d[1].ibyte.bit4=c[1].ibyte.bit3;    /* bit 9 */
        d[1].ibyte.bit5=c[1].ibyte.bit4;    /* bit 10 */
        d[1].ibyte.bit6=c[1].ibyte.bit5;    /* bit 11 */
        d[1].ibyte.bit7=c[1].ibyte.bit6;    /* bit 12 */

        /* key[2] */
        d[2].ibyte.bit0=c[1].ibyte.bit7;    /* bit 13 */
        d[2].ibyte.bit1=c[2].ibyte.bit0;    /* bit 14 */
        d[2].ibyte.bit2=c[2].ibyte.bit1;    /* bit 15 */
        d[2].ibyte.bit3=c[2].ibyte.bit2;    /* bit 16 */
        d[2].ibyte.bit4=c[2].ibyte.bit3;    /* bit 17 */
        d[2].ibyte.bit5=c[2].ibyte.bit4;    /* bit 18 */
        d[2].ibyte.bit6=c[2].ibyte.bit5;    /* bit 19 */
        d[2].ibyte.bit7=c[2].ibyte.bit6;    /* bit 20 */

        /* key[3] */
        d[3].ibyte.bit0=c[2].ibyte.bit7;    /* bit 21 */
        d[3].ibyte.bit1=c[3].ibyte.bit0;    /* bit 22 */
        d[3].ibyte.bit2=c[3].ibyte.bit1;    /* bit 23 */
        d[3].ibyte.bit3=c[3].ibyte.bit2;    /* bit 24 */
        d[3].ibyte.bit4=c[3].ibyte.bit3;    /* bit 25 */
        d[3].ibyte.bit5=c[3].ibyte.bit4;    /* bit 26 */
        d[3].ibyte.bit6=c[3].ibyte.bit5;    /* bit 27 */
        d[3].ibyte.bit7=c[3].ibyte.bit6;    /* bit 28 */
    }
    else {    /* Left rotate 2 bits */
        /* Key[0] */
        d[0].ibyte.bit4=c[3].ibyte.bit6;    /* bit 1 */
        d[0].ibyte.bit5=c[3].ibyte.bit7;    /* bit 2 */

        d[0].ibyte.bit6=c[0].ibyte.bit4;    /* bit 3 */
        d[0].ibyte.bit7=c[0].ibyte.bit5;    /* bit 4 */

        /* key[1] */
        d[1].ibyte.bit0=c[0].ibyte.bit6;    /* bit 5 */
        d[1].ibyte.bit1=c[0].ibyte.bit7;    /* bit 6 */
        d[1].ibyte.bit2=c[1].ibyte.bit0;    /* bit 7 */
        d[1].ibyte.bit3=c[1].ibyte.bit1;    /* bit 8 */
        d[1].ibyte.bit4=c[1].ibyte.bit2;    /* bit 9 */
        d[1].ibyte.bit5=c[1].ibyte.bit3;    /* bit 10 */
        d[1].ibyte.bit6=c[1].ibyte.bit4;    /* bit 11 */
        d[1].ibyte.bit7=c[1].ibyte.bit5;    /* bit 12 */

        /* key[2] */
        d[2].ibyte.bit0=c[1].ibyte.bit6;    /* bit 13 */
        d[2].ibyte.bit1=c[1].ibyte.bit7;    /* bit 14 */
        d[2].ibyte.bit2=c[2].ibyte.bit0;    /* bit 15 */
        d[2].ibyte.bit3=c[2].ibyte.bit1;    /* bit 16 */
        d[2].ibyte.bit4=c[2].ibyte.bit2;    /* bit 17 */
        d[2].ibyte.bit5=c[2].ibyte.bit3;    /* bit 18 */
        d[2].ibyte.bit6=c[2].ibyte.bit4;    /* bit 19 */
        d[2].ibyte.bit7=c[2].ibyte.bit5;    /* bit 20 */

        /* key[3] */
        d[3].ibyte.bit0=c[2].ibyte.bit6;    /* bit 21 */
        d[3].ibyte.bit1=c[2].ibyte.bit7;    /* bit 22 */
        d[3].ibyte.bit2=c[3].ibyte.bit0;    /* bit 23 */
        d[3].ibyte.bit3=c[3].ibyte.bit1;    /* bit 24 */
        d[3].ibyte.bit4=c[3].ibyte.bit2;    /* bit 25 */
        d[3].ibyte.bit5=c[3].ibyte.bit3;    /* bit 26 */
        d[3].ibyte.bit6=c[3].ibyte.bit4;    /* bit 27 */
        d[3].ibyte.bit7=c[3].ibyte.bit5;    /* bit 28 */
    }

    skey[0]=d[0].abyte;
    skey[1]=d[1].abyte;
    skey[2]=d[2].abyte;
    skey[3]=d[3].abyte;
    return;
}

/*-----------------------------------------------------------
DES Gernerate Sub Key procedure
Description:
-----------------------------------------------------------*/
void Gsubkey(char key[8],char subkey[16][6])
{
    int i;
    char cup[4], dup[4];
    char ci[4],  di[4];
    char lsi[16];
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Initial LSi */
    lsi[0]=lsi[1]=lsi[8]=lsi[15]=1;
    lsi[2]=lsi[3]=lsi[4]=lsi[5]=lsi[6]=lsi[7]=2;
    lsi[9]=lsi[10]=lsi[11]=lsi[12]=lsi[13]=lsi[14]=2;


    /* Getout 1 bit of 1 byte: all 56 bytes */
    /* Through PC-1, Get C0, 28 bits */
    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit7;   /* 57 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;   /* 49 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit7;   /* 41 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit7;   /* 33 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit7;   /* 25 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit7;   /* 17 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit7;   /* 9 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit7;   /* 1 bit */
    ci[3]=ipr.abyte;

    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit6;   /* 58 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit6;   /* 50 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit6;   /* 42 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit6;   /* 34 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit6;   /* 26 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit6;   /* 18 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit6;   /* 10 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit6;   /* 2 bit */
    ci[2]=ipr.abyte;

    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit5;   /* 59 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit5;   /* 51 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;   /* 43 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit5;   /* 35 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit5;   /* 27 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit5;   /* 19 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit5;   /* 11 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit5;   /* 3 bit */
    ci[1]=ipr.abyte;

    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit4;   /* 60 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit4;   /* 52 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;   /* 44 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit4;   /* 36 bit */
    ci[0]=ipr.abyte;

    /* Through PC-1, Get D0, 28 bits */
    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit1;   /* 63 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit1;   /* 55 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit1;   /* 47 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit1;   /* 39 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit1;   /* 31 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit1;   /* 23 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit1;   /* 15 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit1;   /* 7 bit */
    di[3]=ipr.abyte;

    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit2;   /* 62 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit2;   /* 54 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit2;   /* 46 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit2;   /* 38 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit2;   /* 30 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit2;   /* 22 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit2;   /* 14 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit2;   /* 6 bit */
    di[2]=ipr.abyte;

    ip1.abyte=key[0];  ipr.ibyte.bit7=ip1.ibyte.bit3;   /* 61 bit */
    ip1.abyte=key[1];  ipr.ibyte.bit6=ip1.ibyte.bit3;   /* 53 bit */
    ip1.abyte=key[2];  ipr.ibyte.bit5=ip1.ibyte.bit3;   /* 45 bit */
    ip1.abyte=key[3];  ipr.ibyte.bit4=ip1.ibyte.bit3;   /* 37 bit */
    ip1.abyte=key[4];  ipr.ibyte.bit3=ip1.ibyte.bit3;   /* 29 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit2=ip1.ibyte.bit3;   /* 21 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit1=ip1.ibyte.bit3;   /* 13 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit0=ip1.ibyte.bit3;   /* 5 bit */
    di[1]=ipr.abyte;

    ip1.abyte=key[4];  ipr.ibyte.bit7=ip1.ibyte.bit4;   /* 28 bit */
    ip1.abyte=key[5];  ipr.ibyte.bit6=ip1.ibyte.bit4;   /* 20 bit */
    ip1.abyte=key[6];  ipr.ibyte.bit5=ip1.ibyte.bit4;   /* 12 bit */
    ip1.abyte=key[7];  ipr.ibyte.bit4=ip1.ibyte.bit4;   /* 4 bit */
    di[0]=ipr.abyte;


    for(i=0;i<16;i=i+1) {
        cup[3]=ci[3]; cup[2]=ci[2]; cup[1]=ci[1]; cup[0]=ci[0];
        dup[3]=di[3]; dup[2]=di[2]; dup[1]=di[1]; dup[0]=di[0];
        /* Generate 16 Subkey */
        rotatebits(cup,ci,lsi[i]);
        rotatebits(dup,di,lsi[i]);
        pc2(ci,di,subkey[i]);
    }

    return;
}

/*-----------------------------------------------------------
DES Main procedure
Description:
-----------------------------------------------------------*/
void des(char m[8],char key[8])
{
    char  ip[8];
    char  lin[4];
    char  rin[4];
    char  lup[4];
    char  rup[4];
    char  tmp[6];
    char  tmp4[4];
    char  subkey[16][6];
    char  i,j;
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Subkey Generate */
    Gsubkey(key,subkey);

    /* IP trans */
    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit6;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit6;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit6;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit6;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit6;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit6;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit6;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit6;
    ip[7]=ipr.abyte;                   /* byte7: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit4;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit4;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit4;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit4;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit4;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit4;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit4;
    ip[6]=ipr.abyte;                   /* byte6: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit2;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit2;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit2;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit2;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit2;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit2;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit2;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit2;
    ip[5]=ipr.abyte;                   /* byte5: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit0;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit0;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit0;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit0;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit0;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit0;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit0;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit0;
    ip[4]=ipr.abyte;                   /* byte4: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit7;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit7;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit7;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit7;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit7;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit7;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit7;
    ip[3]=ipr.abyte;                   /* byte3: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit5;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit5;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit5;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit5;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit5;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit5;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit5;
    ip[2]=ipr.abyte;                   /* byte2: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit3;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit3;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit3;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit3;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit3;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit3;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit3;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit3;
    ip[1]=ipr.abyte;                   /* byte1: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit1;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit1;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit1;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit1;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit1;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit1;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit1;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit1;
    ip[0]=ipr.abyte;                   /* byte0: 8 bits */

    /* Generate L0, R0 */
    lin[3]=ip[7];lin[2]=ip[6];lin[1]=ip[5];lin[0]=ip[4];  /* L0 */
    rin[3]=ip[3];rin[2]=ip[2];rin[1]=ip[1];rin[0]=ip[0];  /* R0 */

    /* Generate Ri, Li (16 Times) */
    for(j=0;j<16;j=j+1){

        for(i=0;i<4;i=i+1){  lup[i]=lin[i];  }
        for(i=0;i<4;i=i+1){  rup[i]=rin[i];  }
        /* Expand Operation */
        expand(rup,tmp);
        /* 48 bits MOD 2 */
        for(i=0;i<6;i=i+1){  tmp[i]=tmp[i]^subkey[j][i];  }
        /* Compress Operation */
        compress(tmp,rin);
        /* Permutation */
        permutate(rin,tmp4);
        /* 32 bits MOD 2 */
        for(i=0;i<4;i=i+1){  rin[i]=lup[i]^tmp4[i];  }        /* Ri */
        for(i=0;i<4;i=i+1){  lin[i]=rup[i];  }                /* Li */

    }
    /* Generate R16, L16 */
    for(i=0;i<4;i=i+1){  tmp4[i]= rin[i];  }
    for(i=0;i<4;i=i+1){  rin[i] = lin[i];  }
    for(i=0;i<4;i=i+1){  lin[i] =tmp4[i];  }


    /* IP(-1) trans */
    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit0;   /* 40 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit0;   /* 8 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit0;   /* 48 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit0;   /* 16 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit0;   /* 56 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit0;   /* 24 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit0;   /* 64 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit0;   /* 32 */
    ip[7]=ipr.abyte;                   /* byte7: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit1;   /* 39 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit1;   /* 7 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit1;   /* 47 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit1;   /* 15 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit1;   /* 55 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit1;   /* 23 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit1;   /* 63 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit1;   /* 31 */
    ip[6]=ipr.abyte;                   /* byte6: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit2;   /* 38 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit2;   /* 6 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit2;   /* 46 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit2;   /* 14 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit2;   /* 54 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit2;   /* 22 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit2;   /* 62 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit2;   /* 30 */
    ip[5]=ipr.abyte;                   /* byte5: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit3;   /* 37 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit3;   /* 29 */
    ip[4]=ipr.abyte;                   /* byte4: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit4;   /* 36 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit4;   /* 28 */
    ip[3]=ipr.abyte;                   /* byte3: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit5;   /*  */
    ip[2]=ipr.abyte;                   /* byte2: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit6;   /*  */
    ip[1]=ipr.abyte;                   /* byte1: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit7;   /*  */
    ip[0]=ipr.abyte;                   /* byte0: 8 bits */

    m[7]=ip[7];
    m[6]=ip[6];
    m[5]=ip[5];
    m[4]=ip[4];
    m[3]=ip[3];
    m[2]=ip[2];
    m[1]=ip[1];
    m[0]=ip[0];
    return;
}

/*-----------------------------------------------------------
UN-DES Main procedure
Description:
-----------------------------------------------------------*/
void undes(char m[8],char key[8])
{
    char  ip[8];
    char  lin[4];
    char  rin[4];
    char  lup[4];
    char  rup[4];
    char  tmp[6];
    char  tmp4[4];
    char  subkey[16][6];
    char  i,j;
    union hbyte ip1;
    union hbyte ipr;
    ip1.abyte=0;
    ipr.abyte=0;

    /* Subkey Generate */
    Gsubkey(key,subkey);

    /* IP trans */
    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit6;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit6;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit6;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit6;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit6;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit6;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit6;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit6;
    ip[7]=ipr.abyte;                   /* byte7: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit4;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit4;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit4;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit4;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit4;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit4;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit4;
    ip[6]=ipr.abyte;                   /* byte6: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit2;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit2;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit2;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit2;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit2;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit2;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit2;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit2;
    ip[5]=ipr.abyte;                   /* byte5: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit0;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit0;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit0;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit0;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit0;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit0;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit0;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit0;
    ip[4]=ipr.abyte;                   /* byte4: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit7;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit7;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit7;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit7;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit7;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit7;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit7;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit7;
    ip[3]=ipr.abyte;                   /* byte3: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit5;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit5;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit5;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit5;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit5;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit5;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit5;
    ip[2]=ipr.abyte;                   /* byte2: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit3;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit3;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit3;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit3;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit3;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit3;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit3;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit3;
    ip[1]=ipr.abyte;                   /* byte1: 8 bits */

    ip1.abyte=m[0];  ipr.ibyte.bit7=ip1.ibyte.bit1;
    ip1.abyte=m[1];  ipr.ibyte.bit6=ip1.ibyte.bit1;
    ip1.abyte=m[2];  ipr.ibyte.bit5=ip1.ibyte.bit1;
    ip1.abyte=m[3];  ipr.ibyte.bit4=ip1.ibyte.bit1;
    ip1.abyte=m[4];  ipr.ibyte.bit3=ip1.ibyte.bit1;
    ip1.abyte=m[5];  ipr.ibyte.bit2=ip1.ibyte.bit1;
    ip1.abyte=m[6];  ipr.ibyte.bit1=ip1.ibyte.bit1;
    ip1.abyte=m[7];  ipr.ibyte.bit0=ip1.ibyte.bit1;
    ip[0]=ipr.abyte;                   /* byte0: 8 bits */

    /* Generate L0, R0 */
    lin[3]=ip[7];lin[2]=ip[6];lin[1]=ip[5];lin[0]=ip[4];  /* L0 */
    rin[3]=ip[3];rin[2]=ip[2];rin[1]=ip[1];rin[0]=ip[0];  /* R0 */

    /* Generate Ri, Li (16 Times) */
    for(j=0;j<16;j=j+1){

        for(i=0;i<4;i=i+1){  lup[i]=lin[i];  }
        for(i=0;i<4;i=i+1){  rup[i]=rin[i];  }
        /* Expand Operation */
        expand(rup,tmp);
        /* 48 bits MOD 2 */
        for(i=0;i<6;i=i+1){  tmp[i]=tmp[i]^subkey[15-j][i];  }
        /* Compress Operation */
        compress(tmp,rin);
        /* Permutation */
        permutate(rin,tmp4);
        /* 32 bits MOD 2 */
        for(i=0;i<4;i=i+1){  rin[i]=lup[i]^tmp4[i];  }        /* Ri */
        for(i=0;i<4;i=i+1){  lin[i]=rup[i];  }                /* Li */

    }
    /* Generate R16, L16 */
    for(i=0;i<4;i=i+1){  tmp4[i]= rin[i];  }
    for(i=0;i<4;i=i+1){  rin[i] = lin[i];  }
    for(i=0;i<4;i=i+1){  lin[i] =tmp4[i];  }

    /* IP(-1) trans */
    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit0;   /* 40 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit0;   /* 8 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit0;   /* 48 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit0;   /* 16 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit0;   /* 56 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit0;   /* 24 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit0;   /* 64 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit0;   /* 32 */
    ip[7]=ipr.abyte;                   /* byte7: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit1;   /* 39 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit1;   /* 7 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit1;   /* 47 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit1;   /* 15 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit1;   /* 55 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit1;   /* 23 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit1;   /* 63 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit1;   /* 31 */
    ip[6]=ipr.abyte;                   /* byte6: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit2;   /* 38 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit2;   /* 6 */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit2;   /* 46 */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit2;   /* 14 */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit2;   /* 54 */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit2;   /* 22 */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit2;   /* 62 */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit2;   /* 30 */
    ip[5]=ipr.abyte;                   /* byte5: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit3;   /* 37 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit3;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit3;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit3;   /* 29 */
    ip[4]=ipr.abyte;                   /* byte4: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit4;   /* 36 */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit4;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit4;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit4;   /* 28 */
    ip[3]=ipr.abyte;                   /* byte3: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit5;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit5;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit5;   /*  */
    ip[2]=ipr.abyte;                   /* byte2: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit6;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit6;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit6;   /*  */
    ip[1]=ipr.abyte;                   /* byte1: 8 bits */

    ip1.abyte=rin[3];  ipr.ibyte.bit7=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[3];  ipr.ibyte.bit6=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[2];  ipr.ibyte.bit5=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[2];  ipr.ibyte.bit4=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[1];  ipr.ibyte.bit3=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[1];  ipr.ibyte.bit2=ip1.ibyte.bit7;   /*  */
    ip1.abyte=rin[0];  ipr.ibyte.bit1=ip1.ibyte.bit7;   /*  */
    ip1.abyte=lin[0];  ipr.ibyte.bit0=ip1.ibyte.bit7;   /*  */
    ip[0]=ipr.abyte;                   /* byte0: 8 bits */

    m[7]=ip[7];
    m[6]=ip[6];
    m[5]=ip[5];
    m[4]=ip[4];
    m[3]=ip[3];
    m[2]=ip[2];
    m[1]=ip[1];
    m[0]=ip[0];
    return;
}



void SDes(char orientation, char PlainText[8], char Key[8], char Encipher[8])
{
    char m[8];
    char k[8];

    m[0]=PlainText[7];
    m[1]=PlainText[6];
    m[2]=PlainText[5];
    m[3]=PlainText[4];
    m[4]=PlainText[3];
    m[5]=PlainText[2];
    m[6]=PlainText[1];
    m[7]=PlainText[0];

    k[0]=Key[7];
    k[1]=Key[6];
    k[2]=Key[5];
    k[3]=Key[4];
    k[4]=Key[3];
    k[5]=Key[2];
    k[6]=Key[1];
    k[7]=Key[0];

    if (orientation==0)  des(m,k);
    else undes(m,k);

    Encipher[0]=m[7];
    Encipher[1]=m[6];
    Encipher[2]=m[5];
    Encipher[3]=m[4];
    Encipher[4]=m[3];
    Encipher[5]=m[2];
    Encipher[6]=m[1];
    Encipher[7]=m[0];
}


void TDes(char orientation,char *PlainText,char *key, char *ucEncipher)
{

    char En[8];
    if (orientation==0){
        SDes(0,PlainText,key,En);
        SDes(1,En,&key[8],En);
        SDes(0,En,&key[0],ucEncipher);
    }
    else {
        SDes(1,PlainText,key,En);
        SDes(0,En,&key[8],En);
        SDes(1,En,&key[0],ucEncipher);
    }
    return;
}


int cipher2(const char* key,char* plain_text,char* crypted_text,int length)
{
    char t_plain[MAX_CI_LEN];
    char t_crypt[MAX_CI_LEN];
    int en_cnt;
    int pad_cnt=0;
    int i;

    if(length>MAX_CI_LEN) return -1;

    for(i=0;i<length;i++)
        t_plain[i]=*(plain_text+i);

    if(length%8==0)
        en_cnt=length/8;
    else {
        en_cnt=length/8+1;
        pad_cnt=8-length%8;
        for(i=0;i<pad_cnt;i++)
            t_plain[length+i]=0;
    }

    for(i=0;i<en_cnt;i++)
        TDes(0,&t_plain[8*i],triple_des_key,&t_crypt[8*i]);

    tohex(t_crypt, crypted_text, 8 * en_cnt);
    return 0;
}



int decipher2(const char* key,char* plain_text,char* crypted_text,int length)
{
    char t_crypt[MAX_CI_LEN];
    int i;

    for(i=0;i<length/2;i++)
        t_crypt[i]=asc_bcd(crypted_text+i*2);

    for(i=0;i<length/16;i++)
        TDes(1,&t_crypt[8*i],triple_des_key,&plain_text[8*i]);

    plain_text[length/2]=0;

    return 0;
}

int cipher3(const char* key,char* plain_text,char* crypted_text,int length)
{
    char t_plain[MAX_CI_LEN];
    char t_crypt[MAX_CI_LEN];
    int en_cnt;
    int pad_cnt=0;
    int i;
    char usekey[32];

    for(i=0;i<32;i++)
        usekey[i]='\0';

    strncpy(usekey,key,16);
    if(length>MAX_CI_LEN) return -1;

    for(i=0;i<length;i++)
        t_plain[i]=*(plain_text+i);

    if(length%8==0)
        en_cnt=length/8;
    else {
        en_cnt=length/8+1;
        pad_cnt=8-length%8;
        for(i=0;i<pad_cnt;i++)
            t_plain[length+i]=0;
    }

    for(i=0;i<en_cnt;i++)
        TDes(0,&t_plain[8*i],usekey,&t_crypt[8*i]);
    tohex(t_crypt, crypted_text, 8 * en_cnt);
    return 0;
}



int decipher3(const char* key,char* plain_text,char* crypted_text,int length)
{
    char t_crypt[MAX_CI_LEN];
    int i;
    char usekey[32];

    for(i=0;i<32;i++)
        usekey[i]='\0';

    strncpy(usekey,key,16);
    for(i=0;i<length/2;i++)
        t_crypt[i]=asc_bcd(crypted_text+i*2);

    for(i=0;i<length/16;i++)
        TDes(1,&t_crypt[8*i],usekey,&plain_text[8*i]);

    plain_text[length/2]=0;

    return 0;
}

char asc_bcd(char *what)
{
    unsigned char digit;
    unsigned char m;

    digit = (what[0] >= 'a' ? ((what[0]) - 'a')+10 : (what[0] - '0'));
    digit *= 16;
    digit  += (what[1] >= 'a' ? ((what[1]) - 'a')+10 : (what[1] - '0'));
    return(digit);
}

void tohex(const char* ins, char* outs, int len) {
    const char* hex = "0123456789abcdef";
    unsigned int v;
    int i = 0;

    for (i = 0; i < len; ++i) {
        v = (unsigned int)ins[i];
        outs[2 * i] = hex[(v >> 4) & 0x0f];
        outs[2 * i + 1] = hex[v & 0x0f];
    }
    outs[2 * i] = 0x00;
}
