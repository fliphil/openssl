/*------------------------------------------------------------------
 * kdf/kdftest.c - Key Derivation Function KAT tests
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, February 2015
 *
 * Copyright (c) 2015 by Cisco Systems, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/e_os2.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>

#define VERBOSE 0

#if 0
/*
 * bit_string is a buffer that is used to hold output strings, e.g.
 * for printing.
 */
#define MAX_PRINT_STRING_LEN 512
char bit_string[MAX_PRINT_STRING_LEN];

static unsigned char
nibble_to_hex_char (unsigned char nibble)
{
    char buf[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    return buf[nibble & 0xF];
}

static string_hex_string (const void *s, int length)
{
    const unsigned char *str = (const unsigned char*)s;
    int i;

    /* double length, since one octet takes two hex characters */
    length *= 2;

    /* truncate string if it would be too long */
    if (length > MAX_PRINT_STRING_LEN) {
        length = MAX_PRINT_STRING_LEN - 1;
    }

    for (i = 0; i < length; i += 2) {
        bit_string[i]   = nibble_to_hex_char(*str >> 4);
        bit_string[i + 1] = nibble_to_hex_char(*str++ & 0xF);
    }
    bit_string[i] = 0; /* null terminate string */
    return bit_string;
}

/* 
 * this hex 2 binary coversion routine is used to translate vectors taken
 * from NIST in ASCII hex format and covert to a hex string. 
 */
static 
int hex2bin(const char *in, char *out)
    {
    int n1, n2, isodd = 0;
    unsigned char ch;

    n1 = strlen(in);
    if (in[n1 - 1] == '\n')
	n1--;

    if (n1 & 1)
	isodd = 1;

    for (n1=0,n2=0 ; in[n1] && in[n1] != '\n' ; )
	{ /* first byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	if(!in[n1])
	    {
	    out[n2++]=ch;
	    break;
	    }
	/* If input is odd length first digit is least significant: assumes
	 * all digits valid hex and null terminated which is true for the
	 * strings we pass.
	 */
	if (n1 == 1 && isodd)
		{
		out[n2++] = ch;
		continue;
		}
	out[n2] = ch << 4;
	/* second byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	out[n2++] |= ch;
	}
    return n2;
    }
#endif


static 
int test_snmp_kdf (void)
{
    static unsigned char engineID1[] = {
          0x00, 0x00, 0x02, 0xb8, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    static unsigned char engineID2[] = {
          0x80, 0x00, 0x02, 0xb8, 0x05, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 
	  0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 
	  0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56 };
    static const char kat_key1[] = {
          0x62, 0x98, 0x10, 0xa3, 0x1a, 0xdc, 0x31, 0x76, 0x9d, 0xfe, 0xbf, 0x9b, 
	  0xac, 0xba, 0x06, 0xa3, 0xff, 0xd9, 0xc4, 0x9f };
    static const char kat_key2[] = {
          0x3c, 0xd1, 0x21, 0xcb, 0xf3, 0xe8, 0xbf, 0x9e, 0x6d, 0x80, 0xf5, 0xf0, 
	  0x53, 0x83, 0x5b, 0x3c, 0x24, 0x1c, 0xd2, 0x1e };
    int pw_len;
    const char *password1 = "LPUQDLsK";
    const char *password2 = "tcoTIHmwcFlPReRJ";
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int len;
    int ret = 1;

    printf("\nStarting SNMP kdf test...");

    pw_len = strlen(password1);

    if (VERBOSE) {
        printf("\n  Negative tests....");
    }

    len = kdf_snmp(NULL, sizeof(engineID1), password1, pw_len, digest);
    if (len != -1) {
        printf("\n  Negative test failed");
	ret = -1;
	goto err;
    }
    len = kdf_snmp(engineID1, 0, password1, pw_len, digest);
    if (len != -1) {
        printf("\n  Negative test failed");
	ret = -1;
	goto err;
    }
    len = kdf_snmp(engineID1, sizeof(engineID1), NULL, pw_len, digest);
    if (len != -1) {
        printf("\n  Negative test failed");
	ret = -1;
	goto err;
    }
    len = kdf_snmp(engineID1, sizeof(engineID1), password1, 0, digest);
    if (len != -1) {
        printf("\n  Negative test failed");
	ret = -1;
	goto err;
    }
    len = kdf_snmp(engineID1, sizeof(engineID1), password1, pw_len, NULL);
    if (len != -1) {
        printf("\n  Negative test failed");
	ret = -1;
	goto err;
    }

    len = kdf_snmp(engineID1, sizeof(engineID1), password1, pw_len, digest);

    ret = memcmp(digest, kat_key1, SHA_DIGEST_LENGTH);
    if (len != SHA_DIGEST_LENGTH) {
        printf("\nHash length inorrect, len = %d", len);
	ret = -1;
	goto err;
    }
   

    pw_len = strlen(password2);
    len = kdf_snmp(engineID2, sizeof(engineID2), password2, pw_len, digest);

    ret = memcmp(digest, kat_key2, SHA_DIGEST_LENGTH);
    if (len != SHA_DIGEST_LENGTH) {
        printf("\nHash length inorrect, len = %d", len);
	ret = -1;
    }
    if (ret == 0) {
        printf("\n  SNMP KDF passed");
    }
err:
    return ret;
}


static 
int test_srtp_kdf (void)
{
    static char k_master1[] = {
          0xc4, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72, 0x8e, 0x26, 0xad, 0xb5, 
	  0x32, 0x12, 0x98, 0x90 };
    static char k_master2[] = {
          0x4b, 0x26, 0xfa, 0xdc, 0x0a, 0x9b, 0xe8, 0x23, 0xdc, 0xd6, 0xab, 0xc8, 
	  0x2c, 0x04, 0x39, 0x75, 0xa6, 0x03, 0xf0, 0x05, 0x87, 0xb8, 0x75, 0x34, 
	  0x60, 0xba, 0xf0, 0x50, 0x2e, 0xee, 0x66, 0xbb };
    static char master_salt1[] = {
          0x0e, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56, 0x62, 0x40, 0x0e, 0x9d, 
	  0x1b, 0xd6 };
    static char master_salt2[] = {
          0x99, 0x74, 0xa3, 0x00, 0x33, 0x28, 0x84, 0xfb, 0xfa, 0x03, 0x71, 0x8c, 
	  0xe0, 0xe0 };
    static char kdr1[] = {
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static char kdr2[] = {
          0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };
    static char srtp_index1[] = {
          0x48, 0x71, 0x65, 0x64, 0x9c, 0xca };
    static char srtp_index2[] = {
          0x44, 0x6f, 0xd5, 0x93, 0xeb, 0xbc };
    static char srtcp_index1[] = {
          0x56, 0xf3, 0xf1, 0x97 };
    static char srtcp_index2[] = {
          0x6e, 0xe6, 0x30, 0x14 }; 
    static const char kat_ke1[] = {
          0xdc, 0x38, 0x21, 0x92, 0xab, 0x65, 0x10, 0x8a, 0x86, 0xb2, 0x59, 0xb6, 
	  0x1b, 0x3a, 0xf4, 0x6f };
    static const char kat_ka1[] = {
          0xb8, 0x39, 0x37, 0xfb, 0x32, 0x17, 0x92, 0xee, 0x87, 0xb7, 0x88, 0x19, 
	  0x3b, 0xe5, 0xa4, 0xe3, 0xbd, 0x32, 0x6e, 0xe4 };
    static const char kat_ks1[] = {
          0xf1, 0xc0, 0x35, 0xc0, 0x0b, 0x5a, 0x54, 0xa6, 0x16, 0x92, 0xc0, 0x16, 
	  0x27, 0x6c };
    static const char kat_ke2[] = {
          0xab, 0x5b, 0xe0, 0xb4, 0x56, 0x23, 0x5d, 0xcf, 0x77, 0xd5, 0x08, 0x69, 
	  0x29, 0xba, 0xfb, 0x38 };
    static const char kat_ka2[] = {
          0xc5, 0x2f, 0xde, 0x0b, 0x80, 0xb0, 0xf0, 0xba, 0xd8, 0xd1, 0x56, 0x45, 
	  0xcb, 0x86, 0xe7, 0xc7, 0xc3, 0xd8, 0x77, 0x0e };
    static const char kat_ks2[] = {
          0xde, 0xb5, 0xf8, 0x5f, 0x81, 0x33, 0x6a, 0x96, 0x5e, 0xd3, 0x2b, 0xb7, 
	  0xed, 0xe8 };
    static const char kat_ke3[] = {
          0xd2, 0xc2, 0xe6, 0xeb, 0x48, 0xcc, 0xcd, 0xe4, 0x4f, 0x24, 0x2f, 0x4f, 
	  0xbf, 0x40, 0xbd, 0xb4, 0x26, 0x9c, 0xc8, 0x61, 0xf6, 0x0c, 0xfa, 0xbf, 
	  0x01, 0xec, 0x89, 0xd4, 0x1f, 0xce, 0x60, 0x1e };
    static const char kat_ka3[] = {
          0x93, 0x12, 0x0f, 0x64, 0xa9, 0x63, 0x15, 0xf8, 0x06, 0xfa, 0xd4, 0x28, 
	  0xf9, 0xe3, 0x7b, 0xf0, 0xac, 0x16, 0x45, 0xd9 };
    static const char kat_ks3[] = {
          0xc7, 0x29, 0xf8, 0x05, 0xc7, 0xf9, 0x0d, 0x8c, 0x25, 0x2c, 0x28, 0x36, 
	  0x63, 0x39 };
    static const char kat_ke4[] = {
          0x89, 0xa6, 0x4f, 0x9f, 0x44, 0x58, 0x1c, 0xab, 0x9b, 0x1b, 0x4c, 0x8f, 
	  0x19, 0x79, 0x71, 0x28, 0xf7, 0xf4, 0x60, 0xcd, 0xda, 0x01, 0xa0, 0xcd, 
	  0x3c, 0x52, 0xab, 0xd9, 0x62, 0xb6, 0x9f, 0x20 };
    static const char kat_ka4[] = {
          0x49, 0x34, 0x54, 0xb8, 0x5a, 0x88, 0xb0, 0x56, 0x7c, 0x94, 0x78, 0x8a, 
	  0xa8, 0x08, 0x1c, 0xf3, 0xc5, 0x5a, 0x12, 0x17 };
    static const char kat_ks4[] = {
          0x5c, 0x4e, 0x98, 0xd3, 0x29, 0x6e, 0x00, 0x9b, 0x45, 0x38, 0x09, 0x6d, 
	  0x72, 0xe4 };
    char *k_e = NULL, *k_a = NULL, *k_s = NULL;
    int ret;
    const EVP_CIPHER *cipher;

    printf("\nStarting SRTP kdf test...");

    k_e = malloc(64);
    k_a = malloc(64);
    k_s = malloc(64);
    if (!k_e || !k_a || !k_s) {
        printf("\nFailed to allocate memory for SRTP KAT");
	return -1;
    }
    memset(k_e, 0, 64);
    memset(k_a, 0, 64);
    memset(k_s, 0, 64);

    cipher = EVP_aes_128_ctr();

    if (VERBOSE) {
        printf("\n  Negative tests....");
    }
    ret = kdf_srtp(NULL, k_master1, master_salt1, kdr1, srtp_index1,
                   02, k_s);
    if (ret != -1) {
        printf("\n  SRTP KDF failed negative parameter test");
	goto err;
    }
    ret = kdf_srtp(cipher, NULL, master_salt1, kdr1, srtp_index1,
                   02, k_s);
    if (ret != -1) {
        printf("\n  SRTP KDF failed negative parameter test");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, NULL, kdr1, srtp_index1,
                   02, k_s);
    if (ret != -1) {
        printf("\n  SRTP KDF failed negative parameter test");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtp_index1,
                   06, k_s);
    if (ret != -1) {
        printf("\n  SRTP KDF failed negative parameter test");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtp_index1,
                   02, NULL);
    if (ret != -1) {
        printf("\n  SRTP KDF failed negative parameter test");
	goto err;
    }

    memset(k_e, 0, 64);
    memset(k_a, 0, 64);
    memset(k_s, 0, 64);
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtp_index1,
                   00, k_e);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_e1");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtp_index1,
                   01, k_a);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_a1");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtp_index1,
                   02, k_s);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_s1");
	goto err;
    }

    ret = memcmp(k_e, kat_ke1, sizeof(kat_ke1));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_e1 compare");
	goto err;
    }

    ret = memcmp(k_a, kat_ka1, sizeof(kat_ka1));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_a1 compare");
	goto err;
    }

    ret = memcmp(k_s, kat_ks1, sizeof(kat_ks1));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_s1 compare");
	goto err;
    }


    memset(k_e, 0, 64);
    memset(k_a, 0, 64);
    memset(k_s, 0, 64);
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtcp_index1,
                   03, k_e);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_e2");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtcp_index1,
                   04, k_a);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_a2");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master1, master_salt1, kdr1, srtcp_index1,
                   05, k_s);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_s2");
	goto err;
    }


    ret = memcmp(k_e, kat_ke2, sizeof(kat_ke2));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_e2 compare");
	goto err;
    }
    ret = memcmp(k_a, kat_ka2, sizeof(kat_ka2));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_a2 compare");
	goto err;
    }
    ret = memcmp(k_s, kat_ks2, sizeof(kat_ks2));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_s2 compare");
	goto err;
    }

    cipher = EVP_aes_256_ctr();

    memset(k_e, 0, 64);
    memset(k_a, 0, 64);
    memset(k_s, 0, 64);
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtp_index2,
                   00, k_e);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_e3");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtp_index2,
                   01, k_a);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_a3");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtp_index2,
                   02, k_s);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_s3");
	goto err;
    }


    ret = memcmp(k_e, kat_ke3, sizeof(kat_ke3));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_e3 compare");
	goto err;
    }
    ret = memcmp(k_a, kat_ka3, sizeof(kat_ka3));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_a3 compare");
	goto err;
    }
    ret = memcmp(k_s, kat_ks3, sizeof(kat_ks3));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_s3 compare");
	goto err;
    }

    memset(k_e, 0, 64);
    memset(k_a, 0, 64);
    memset(k_s, 0, 64);
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtcp_index2,
                   03, k_e);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_e4");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtcp_index2,
                   04, k_a);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_a4");
	goto err;
    }
    ret = kdf_srtp(cipher, k_master2, master_salt2, kdr2, srtcp_index2,
                   05, k_s);
    if (ret == -1) {
        printf("\n  SRTP KDF failed on kdf_srtp k_s4");
	goto err;
    }

    ret = memcmp(k_e, kat_ke4, sizeof(kat_ke4));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_e4 compare");
	goto err;
    }
    ret = memcmp(k_a, kat_ka4, sizeof(kat_ka4));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_a4 compare");
	goto err;
    }
    ret = memcmp(k_s, kat_ks4, sizeof(kat_ks4));
    if (ret != 0) {
        printf("\n  SRTP KDF failed on SRTP k_s4 compare");
	goto err;
    }
    printf("\n  SRTP KDF passed");

err:
    free(k_e);
    free(k_a);
    free(k_s);

    return ret;
}


static 
int test_ssh_kdf (void)
{
    static char K[] = {
          0x00, 0x00, 0x00, 0x80, 0x55, 0xba, 0xe9, 0x31, 0xc0, 0x7f, 0xd8, 0x24, 
	  0xbf, 0x10, 0xad, 0xd1, 0x90, 0x2b, 0x6f, 0xbc, 0x7c, 0x66, 0x53, 0x47, 
	  0x38, 0x34, 0x98, 0xa6, 0x86, 0x92, 0x9f, 0xf5, 0xa2, 0x5f, 0x8e, 0x40, 
	  0xcb, 0x66, 0x45, 0xea, 0x81, 0x4f, 0xb1, 0xa5, 0xe0, 0xa1, 0x1f, 0x85, 
	  0x2f, 0x86, 0x25, 0x56, 0x41, 0xe5, 0xed, 0x98, 0x6e, 0x83, 0xa7, 0x8b, 
	  0xc8, 0x26, 0x94, 0x80, 0xea, 0xc0, 0xb0, 0xdf, 0xd7, 0x70, 0xca, 0xb9, 
	  0x2e, 0x7a, 0x28, 0xdd, 0x87, 0xff, 0x45, 0x24, 0x66, 0xd6, 0xae, 0x86, 
	  0x7c, 0xea, 0xd6, 0x3b, 0x36, 0x6b, 0x1c, 0x28, 0x6e, 0x6c, 0x48, 0x11, 
	  0xa9, 0xf1, 0x4c, 0x27, 0xae, 0xa1, 0x4c, 0x51, 0x71, 0xd4, 0x9b, 0x78, 
	  0xc0, 0x6e, 0x37, 0x35, 0xd3, 0x6e, 0x6a, 0x3b, 0xe3, 0x21, 0xdd, 0x5f, 
	  0xc8, 0x23, 0x08, 0xf3, 0x4e, 0xe1, 0xcb, 0x17, 0xfb, 0xa9, 0x4a, 0x59 };
    static char H[] = {
          0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92, 0xb5, 0x11, 0x2d, 0xcd, 
	  0x75, 0xa1, 0x07, 0x5f, 0xdc, 0x88, 0x92, 0x45 };
    static char session_id[] = {
          0xa4, 0xeb, 0xd4, 0x59, 0x34, 0xf5, 0x67, 0x92, 0xb5, 0x11, 0x2d, 0xcd, 
	  0x75, 0xa1, 0x07, 0x5f, 0xdc, 0x88, 0x92, 0x45 };
    static const char client_iv[] = {
          0xe2, 0xf6, 0x27, 0xc0, 0xb4, 0x3f, 0x1a, 0xc1 };
    static const char server_iv[] = {
          0x58, 0x47, 0x14, 0x45, 0xf3, 0x42, 0xb1, 0x81 };
    static const char key1[]  = {
          0x1c, 0xa9, 0xd3, 0x10, 0xf8, 0x6d, 0x51, 0xf6, 0xcb, 0x8e, 0x70, 0x07, 
	  0xcb, 0x2b, 0x22, 0x0d, 0x55, 0xc5, 0x28, 0x1c, 0xe6, 0x80, 0xb5, 0x33 };
    static const char key2[] = {
          0x2c, 0x60, 0xdf, 0x86, 0x03, 0xd3, 0x4c, 0xc1, 0xdb, 0xb0, 0x3c, 0x11, 
	  0xf7, 0x25, 0xa4, 0x4b, 0x44, 0x00, 0x88, 0x51, 0xc7, 0x3d, 0x68, 0x44 };
    static const char key3[] = {
          0x47, 0x2e, 0xb8, 0xa2, 0x61, 0x66, 0xae, 0x6a, 0xa8, 0xe0, 0x68, 0x68, 
	  0xe4, 0x5c, 0x3b, 0x26, 0xe6, 0xee, 0xed, 0x06 };
    static const char key4[] = {
          0xe3, 0xe2, 0xfd, 0xb9, 0xd7, 0xbc, 0x21, 0x16, 0x5a, 0x3d, 0xbe, 0x47, 
	  0xe1, 0xec, 0xeb, 0x77, 0x64, 0x39, 0x0b, 0xab };
    int ret;
    int civ_len, k_len, siv_len, sid_len, h_len, k1_len, k2_len, k3_len, k4_len;
    const EVP_MD *evp_md;
    unsigned char *buffer;

    printf("\nStarting SSH kdf test...");

    buffer = malloc(1024);
    if (!buffer) {
        printf("\nFailed to allocate memory for SSH KAT");
	return -1;
    }

    civ_len = sizeof(client_iv);
    k_len = sizeof(K);
    sid_len = sizeof(session_id);
    siv_len = sizeof(server_iv);
    h_len = sizeof(H);
    k1_len = sizeof(key1);
    k2_len = sizeof(key2);
    k3_len = sizeof(key3);
    k4_len = sizeof(key4);

    evp_md = EVP_sha1();

    if (VERBOSE) printf("\n  Negative SSH kdf testing");
    ret = kdf_ssh(NULL, 'A', civ_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 0, civ_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', 0, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, NULL, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, 0, session_id, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, NULL, sid_len, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, session_id, 0, H, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, session_id, sid_len, NULL, h_len, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, session_id, sid_len, H, 0, buffer);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }
    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, session_id, sid_len, H, h_len, NULL);
    if (ret != -1) {
        printf("\n  SNMP KDF negative test failed on SSH kdf");
	goto err;
    }


    ret = kdf_ssh(evp_md, 'A', civ_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH client_iv");
	goto err;
    }

    ret = memcmp(client_iv, buffer, civ_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH client_iv compare");
	goto err;
    }

    ret = kdf_ssh(evp_md, 'B', siv_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH server_iv");
	goto err;
    }

    ret = memcmp(server_iv, buffer, siv_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH server_iv compare");
	goto err;
    }

    ret = kdf_ssh(evp_md, 'C', k1_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k1");
	goto err;
    }

    ret = memcmp(key1, buffer, k1_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k1 compare");
	goto err;
    }

    ret = kdf_ssh(evp_md, 'D', k2_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k2");
	goto err;
    }

    ret = memcmp(key2, buffer, k2_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k2 compare");
	goto err;
    }

    ret = kdf_ssh(evp_md, 'E', k3_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k3");
	goto err;
    }

    ret = memcmp(key3, buffer, k3_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k3 compare");
	goto err;
    }

    ret = kdf_ssh(evp_md, 'F', k4_len, K, k_len, session_id, sid_len, H, h_len, buffer);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k4");
	goto err;
    }

    ret = memcmp(key4, buffer, k4_len);
    if (ret != 0) {
        printf("\n  SNMP KDF failed on SSH k4 compare");
	goto err;
    }
    printf("\n  SSH KDF passed");
err:
    free(buffer);

    return ret;
}

static
int test_802_11i_kdf(void)
{
    int len = 128; //needed key length in bits
    static unsigned char key[] = {
          0xab, 0x05, 0x2e, 0xf2, 0xe9, 0x13, 0x74, 0x15, 0x06, 0x04, 0x35, 0xb9, 
	  0xa7, 0x3a, 0x67, 0x62, 0x3e, 0x07, 0xf3, 0x46, 0x79, 0x81, 0xfe, 0x80, 
	  0x93, 0xc4, 0x40, 0x97, 0x36, 0x58, 0x85, 0x10, 0x28, 0xc8, 0x6e, 0x44, 
	  0xa1, 0xfd, 0x91, 0x00, 0xb4, 0x13, 0x79, 0x2f, 0x14, 0xe2, 0x57, 0x68, 
	  0x3a, 0xa7, 0x4b, 0x83, 0xec, 0xd9, 0x6d, 0x24, 0xc8, 0x62, 0xc2, 0x26, 
	  0x3a, 0x49, 0x6c, 0xfb };
    static unsigned char fixed_data[] = {
          0x66, 0x88, 0x31, 0xe2, 0x70, 0x18, 0x03, 0x58, 0x1e, 0xb9, 0x08, 0x3a, 
	  0x09, 0x28, 0xcc, 0x00, 0xd8, 0x3a, 0x3c, 0x19, 0xca, 0x4d, 0xf0, 0x61, 
	  0xd1, 0x55, 0xa8, 0x80, 0xa6, 0x6b, 0xa2, 0x48, 0x57, 0xad, 0x6f, 0x4b, 
	  0xd7, 0xa6, 0x73, 0x82, 0x21, 0x5b, 0x5b, 0x9d, 0x81, 0xb3, 0x77, 0x37, 
	  0xd7, 0x4f, 0x7a, 0x5e, 0xf7, 0x84, 0x86, 0xae, 0xea, 0x2f, 0x9a, 0xc1 };
    static const char key_out[] = {
          0x6e, 0xc2, 0xb0, 0x89, 0x10, 0x70, 0x21, 0x46, 0x3b, 0xae, 0x15, 0xf8, 
	  0xf5, 0xc7, 0x71, 0xab };
    unsigned char out[1024];
    int k_len, fd_len, ko_len, ret;
    const EVP_MD *evp_md;

    printf("\nStarting SP800-108/802.11i kdf test...");

    memset(out, 0 , 1024);

    k_len = sizeof(key);
    ko_len = sizeof(key_out);
    fd_len = sizeof(fixed_data);
    evp_md = EVP_sha512();

    /* negative API tests */
    ret = kdf_802_11i(NULL, k_len, NULL, 0, fixed_data, fd_len, out, len/8 + evp_md->md_size, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, 0, NULL, 0, fixed_data, fd_len, out, len/8 + evp_md->md_size, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, k_len, NULL, 0, NULL, fd_len, out, len/8 + evp_md->md_size, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, k_len, NULL, 0, fixed_data, 0, out, len/8 + evp_md->md_size, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, k_len, NULL, 0, fixed_data, fd_len, NULL, len/8 + evp_md->md_size, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, k_len, NULL, 0, fixed_data, fd_len, out, 0, evp_md);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    ret = kdf_802_11i(key, k_len, NULL, 0, fixed_data, fd_len, out, len/8 + evp_md->md_size, NULL);
    if (ret != -1) {
        printf("\nKDF negative tests for 800-108 failed");
	goto err;
    }

    /* 
     * Note that the length passed in has one md_size added since the kdf
     * was written to 802.11i specs.  It starts the counter at zero, not one.
     * In order to operate as SP800-108 requires we add one md_size so it 
     * makes an extra pass, ie bumps the counter one extra.
     */
    ret = kdf_802_11i(key, k_len, NULL, 0, fixed_data, fd_len, out, len/8 + evp_md->md_size, evp_md);
    if (ret != evp_md->md_size) {
        printf("\nKDF for 800-108 failed to return proper length");
	goto err;
    }

    /*
     * Note that when expecting SP800-108 output, we must skip the first
     * md_size of data because that was using a counter value of zero.
     * Starting with the second md block, with counter value of one, is
     * where the SP800-108 data starts.  This KAT was taken from the NIST
     * sample vectors and therefore uses SP800-108.
     */
    ret = memcmp(key_out, out + evp_md->md_size, ko_len);
    if (ret != 0) {
        printf("\n  800-018 KDF failed on compare");
	goto err;
    }
    printf("\n  SP800-108/802.11i KDF passed");
err:

    return 0;
}

static int test_tls_kdf (void)
{
    static const char pms1[] = {
          0xf8, 0x93, 0x8e, 0xcc, 0x9e, 0xde, 0xbc, 0x50, 0x30, 0xc0, 0xc6, 0xa4, 
	  0x41, 0xe2, 0x13, 0xcd, 0x24, 0xe6, 0xf7, 0x70, 0xa5, 0x0d, 0xda, 0x07, 
	  0x87, 0x6f, 0x8d, 0x55, 0xda, 0x06, 0x2b, 0xca, 0xdb, 0x38, 0x6b, 0x41, 
	  0x1f, 0xd4, 0xfe, 0x43, 0x13, 0xa6, 0x04, 0xfc, 0xe6, 0xc1, 0x7f, 0xbc };

    static const char shr1[] = {
          0xf6, 0xc9, 0x57, 0x5e, 0xd7, 0xdd, 0xd7, 0x3e, 0x1f, 0x7d, 0x16, 0xec, 
	  0xa1, 0x15, 0x41, 0x58, 0x12, 0xa4, 0x3c, 0x2b, 0x74, 0x7d, 0xaa, 0xaa, 
	  0xe0, 0x43, 0xab, 0xfb, 0x50, 0x05, 0x3f, 0xce };

    static const char chr1[] = {
          0x36, 0xc1, 0x29, 0xd0, 0x1a, 0x32, 0x00, 0x89, 0x4b, 0x91, 0x79, 0xfa, 
	  0xac, 0x58, 0x9d, 0x98, 0x35, 0xd5, 0x87, 0x75, 0xf9, 0xb5, 0xea, 0x35, 
	  0x87, 0xcb, 0x8f, 0xd0, 0x36, 0x4c, 0xae, 0x8c };

    static const char sr1[] = {
          0xae, 0x6c, 0x80, 0x6f, 0x8a, 0xd4, 0xd8, 0x07, 0x84, 0x54, 0x9d, 0xff, 
	  0x28, 0xa4, 0xb5, 0x8f, 0xd8, 0x37, 0x68, 0x1a, 0x51, 0xd9, 0x28, 0xc3, 
	  0xe3, 0x0e, 0xe5, 0xff, 0x14, 0xf3, 0x98, 0x68 };

    static const char cr1[] = {
          0x62, 0xe1, 0xfd, 0x91, 0xf2, 0x3f, 0x55, 0x8a, 0x60, 0x5f, 0x28, 0x47, 
	  0x8c, 0x58, 0xcf, 0x72, 0x63, 0x7b, 0x89, 0x78, 0x4d, 0x95, 0x9d, 0xf7, 
	  0xe9, 0x46, 0xd3, 0xf0, 0x7b, 0xd1, 0xb6, 0x16 };

    static const char mkat1[] = {
          0x20, 0x2c, 0x88, 0xc0, 0x0f, 0x84, 0xa1, 0x7a, 0x20, 0x02, 0x70, 0x79, 
	  0x60, 0x47, 0x87, 0x46, 0x11, 0x76, 0x45, 0x55, 0x39, 0xe7, 0x05, 0xbe, 
	  0x73, 0x08, 0x90, 0x60, 0x2c, 0x28, 0x9a, 0x50, 0x01, 0xe3, 0x4e, 0xeb, 
	  0x3a, 0x04, 0x3e, 0x5d, 0x52, 0xa6, 0x5e, 0x66, 0x12, 0x51, 0x88, 0xbf, 
	  00 };

    static const char kkat1[] = {
          0xd0, 0x61, 0x39, 0x88, 0x9f, 0xff, 0xac, 0x1e, 0x3a, 0x71, 0x86, 0x5f, 
	  0x50, 0x4a, 0xa5, 0xd0, 0xd2, 0xa2, 0xe8, 0x95, 0x06, 0xc6, 0xf2, 0x27, 
	  0x9b, 0x67, 0x0c, 0x3e, 0x1b, 0x74, 0xf5, 0x31, 0x01, 0x6a, 0x25, 0x30, 
	  0xc5, 0x1a, 0x3a, 0x0f, 0x7e, 0x1d, 0x65, 0x90, 0xd0, 0xf0, 0x56, 0x6b, 
	  0x2f, 0x38, 0x7f, 0x8d, 0x11, 0xfd, 0x4f, 0x73, 0x1c, 0xdd, 0x57, 0x2d, 
	  0x2e, 0xae, 0x92, 0x7f, 0x6f, 0x2f, 0x81, 0x41, 0x0b, 0x25, 0xe6, 0x96, 
	  0x0b, 0xe6, 0x89, 0x85, 0xad, 0xd6, 0xc3, 0x84, 0x45, 0xad, 0x9f, 0x8c, 
	  0x64, 0xbf, 0x80, 0x68, 0xbf, 0x9a, 0x66, 0x79, 0x48, 0x5d, 0x96, 0x6f, 
	  0x1a, 0xd6, 0xf6, 0x8b, 0x43, 0x49, 0x5b, 0x10, 0xa6, 0x83, 0x75, 0x5e, 
	  0xa2, 0xb8, 0x58, 0xd7, 0x0c, 0xca, 0xc7, 0xec, 0x8b, 0x05, 0x3c, 0x6b, 
	  0xd4, 0x1c, 0xa2, 0x99, 0xd4, 0xe5, 0x19, 0x28 };

#ifdef OPENSSL_KDF_TLS1
    static const char pms2[] = {
          0xbd, 0xed, 0x7f, 0xa5, 0xc1, 0x69, 0x9c, 0x01, 0x0b, 0xe2, 0x3d, 0xd0, 
	  0x6a, 0xda, 0x3a, 0x48, 0x34, 0x9f, 0x21, 0xe5, 0xf8, 0x62, 0x63, 0xd5, 
	  0x12, 0xc0, 0xc5, 0xcc, 0x37, 0x9f, 0x0e, 0x78, 0x0e, 0xc5, 0x5d, 0x98, 
	  0x44, 0xb2, 0xf1, 0xdb, 0x02, 0xa9, 0x64, 0x53, 0x51, 0x35, 0x68, 0xd0, 
	  00 };

    static const char shr2[] = {
          0x13, 0x5e, 0x4d, 0x55, 0x7f, 0xdf, 0x3a, 0xa6, 0x40, 0x6d, 0x82, 0x97, 
	  0x5d, 0x5c, 0x60, 0x6a, 0x97, 0x34, 0xc9, 0x33, 0x4b, 0x42, 0x13, 0x6e, 
	  0x96, 0x99, 0x0f, 0xbd, 0x53, 0x58, 0xcd, 0xb2 };

    static const char chr2[] = {
          0xe5, 0xac, 0xaf, 0x54, 0x9c, 0xd2, 0x5c, 0x22, 0xd9, 0x64, 0xc0, 0xd9, 
	  0x30, 0xfa, 0x4b, 0x52, 0x61, 0xd2, 0x50, 0x7f, 0xad, 0x84, 0xc3, 0x37, 
	  0x15, 0xb7, 0xb9, 0xa8, 0x64, 0x02, 0x06, 0x93 };

    static const char sr2[] = {
          0x67, 0x26, 0x7e, 0x65, 0x0e, 0xb3, 0x24, 0x44, 0x11, 0x9d, 0x22, 0x2a, 
	  0x36, 0x8c, 0x19, 0x1a, 0xf3, 0x08, 0x28, 0x88, 0xdc, 0x35, 0xaf, 0xe8, 
	  0x36, 0x8e, 0x63, 0x8c, 0x82, 0x88, 0x74, 0xbe };

    static const char cr2[] = {
          0xd5, 0x8a, 0x7b, 0x1c, 0xd4, 0xfe, 0xda, 0xa2, 0x32, 0x15, 0x9d, 0xf6, 
	  0x52, 0xce, 0x18, 0x8f, 0x9d, 0x99, 0x7e, 0x06, 0x1b, 0x9b, 0xf4, 0x8e, 
	  0x83, 0xb6, 0x29, 0x90, 0x44, 0x09, 0x31, 0xf6 };

    static const char mkat2[] = {
          0x2f, 0x69, 0x62, 0xdf, 0xbc, 0x74, 0x4c, 0x4b, 0x21, 0x38, 0xbb, 0x6b, 
	  0x3d, 0x33, 0x05, 0x4c, 0x5e, 0xcc, 0x14, 0xf2, 0x48, 0x51, 0xd9, 0x89, 
	  0x63, 0x95, 0xa4, 0x4a, 0xb3, 0x96, 0x4e, 0xfc, 0x20, 0x90, 0xc5, 0xbf, 
	  0x51, 0xa0, 0x89, 0x12, 0x09, 0xf4, 0x6c, 0x1e, 0x1e, 0x99, 0x8f, 0x62, 
	  00 };

    static const char kkat2[] = {
          0x30, 0x88, 0x82, 0x59, 0x88, 0xe7, 0x7f, 0xce, 0x68, 0xd1, 0x9f, 0x75, 
	  0x6e, 0x18, 0xe4, 0x3e, 0xb7, 0xfe, 0x67, 0x24, 0x33, 0x50, 0x4f, 0xea, 
	  0xf9, 0x9b, 0x3c, 0x50, 0x3d, 0x90, 0x91, 0xb1, 0x64, 0xf1, 0x66, 0xdb, 
	  0x30, 0x1d, 0x70, 0xc9, 0xfc, 0x08, 0x70, 0xb4, 0xa9, 0x45, 0x63, 0x90, 
	  0x7b, 0xee, 0x1a, 0x61, 0xfb, 0x78, 0x6c, 0xb7, 0x17, 0x57, 0x68, 0x90, 
	  0xbc, 0xc5, 0x1c, 0xb9, 0xea, 0xd9, 0x7e, 0x01, 0xd0, 0xa2, 0xfe, 0xa9, 
	  0x9c, 0x95, 0x33, 0x77, 0xb1, 0x95, 0x20, 0x5f, 0xf0, 0x7b, 0x36, 0x95, 
	  0x89, 0x17, 0x87, 0x96, 0xed, 0xc9, 0x63, 0xfd, 0x80, 0xfd, 0xbe, 0x51, 
	  0x8a, 0x2f, 0xc1, 0xc3, 0x5c, 0x18, 0xae, 0x8d };
    int len, len1, pms2_len;
#endif
    int olen1, olen2;
    unsigned char *master_secret1 = NULL;
    unsigned char *master_secret2 = NULL;
    unsigned char *key_block1 = NULL;
    unsigned char *key_block2 = NULL;
    int ret, i;
    const EVP_MD *evp_md;


    printf("\nStarting TLS kdf test...");

    master_secret1 = malloc(4096);
    master_secret2 = malloc(4096);
    key_block1 = malloc(4096);
    key_block2 = malloc(4096);
    olen1 = 48;
    olen2 = 128;

    if (!master_secret1 || !key_block1 || !master_secret2 || !key_block2) {
	printf("\nFailed to malloc memory for tls");
	return -1;
    }

    memset(master_secret1, 0, 4096);
    memset(key_block1, 0, 4096);

    evp_md = EVP_sha256();
    /* negative API testing */
    ret = kdf_tls12_P_hash(NULL, (const unsigned char *)pms1, sizeof(pms1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   master_secret1, olen1);

    if (ret != 0) {
	printf("\nKDF TLS negative testing");
	return -1;
    }
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)NULL, sizeof(pms1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   master_secret1, olen1);

    if (ret != 0) {
	printf("\nKDF TLS negative testing");
	return -1;
    }

    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms1, 0, 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   master_secret1, olen1);

    if (ret != 0) {
	printf("\nKDF TLS negative testing");
	return -1;
    }

    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms1, sizeof(pms1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   NULL, olen1);

    if (ret != 0) {
	printf("\nKDF TLS negative testing");
	return -1;
    }

    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms1, sizeof(pms1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   master_secret1, 0);

    if (ret != 0) {
	printf("\nKDF TLS negative testing");
	return -1;
    }

    /* TLS 1.2 */
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms1, sizeof(pms1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr1, sizeof(chr1),
			   shr1, sizeof(shr1),
			   NULL, 0,
			   NULL, 0,
			   master_secret1, olen1);

    if (ret == 0) {
	printf("\nKDF TLS failed on master secret");
	return -1;
    }

    i = memcmp(master_secret1, mkat1, sizeof(mkat1));
    if (i != 0) {
	printf("\nKDF TLS failed on master secret compare");
	return -1;
    }

    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)master_secret1, olen1,
		           TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
			   sr1, sizeof(sr1),
			   cr1, sizeof(cr1),
			   NULL, 0,
			   NULL, 0,
			   key_block1, olen2);

    if (ret == 0) {
	printf("\nKDF TLS failed on expansion");
	return -1;
    }
    i = memcmp(key_block1, kkat1, sizeof(kkat1));
    if (i != 0) {
	printf("\nKDF TLS failed on expansion compare");
	return -1;
    }

#ifdef OPENSSL_KDF_TLS1
    /* TLS 1.0/1.1 */
    memset(master_secret1, 0, 4096);
    memset(master_secret2, 0, 4096);
    memset(key_block1, 0, 4096);
    memset(key_block2, 0, 4096);

    olen1 = 48;
    olen2 = 104;
    len1 = olen1;

    pms2_len = sizeof(pms2);
    len = pms2_len / 2;

    evp_md = EVP_md5();
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms2, len + (pms2_len & 1), 
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr2, sizeof(chr2),
			   shr2, sizeof(shr2),
			   NULL, 0,
			   NULL, 0,
			   master_secret2, olen1);

    if (ret == 0) {
	printf("\nKDF TLS 1.0/1.1 failed on master secret");
	return -1;
    }
    for (i = 0; i < olen1; i++) {
        master_secret1[i] ^= master_secret2[i];
    }

    evp_md = EVP_sha1();
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)pms2 + len, len + (pms2_len & 1),
	                   TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
			   chr2, sizeof(chr2),
			   shr2, sizeof(shr2),
			   NULL, 0,
			   NULL, 0,
			   master_secret2, olen1);

    for (i = 0; i < olen1; i++) {
        master_secret1[i] ^= master_secret2[i];
    }

    i = memcmp(master_secret1, mkat2, sizeof(mkat2));
    if (i != 0) {
	printf("\nKDF TLS 1.0/1.1 failed on master secret compare");
	return -1;
    }

    len = len1 / 2;

    evp_md = EVP_md5();
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)master_secret1, 
			   len + (len1 & 1),
		           TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
			   sr2, sizeof(sr2),
			   cr2, sizeof(cr2),
			   NULL, 0,
			   NULL, 0,
			   key_block2, olen2);
    if (ret == 0) {
	printf("\nKDF TLS 1.0/1.1 failed on expansion");
	return -1;
    }
    for (i = 0; i < olen2; i++) {
        key_block1[i] ^= key_block2[i];
    }    

    evp_md = EVP_sha1();
    ret = kdf_tls12_P_hash(evp_md, (const unsigned char *)master_secret1 + len,
		           len + (len1 & 1),
		           TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
			   sr, sr_len,
			   cr, cr_len,
			   NULL, 0,
			   NULL, 0,
			  key_block2, olen2);
    if (ret == 0) {
	printf("\nKDF TLS 1.0/1.1 failed on expansion");
	return -1;
    }
    for (i = 0; i < olen2; i++) {
        key_block1[i] ^= key_block2[i];
    }

    i = memcmp(key_block1, kkat2, sizeof(kkat2));
    if (i != 0) {
	printf("\nKDF TLS 1.0/1.1 failed on expansion compare");
	return -1;
    }

#endif
    printf("\n  TLS KDF passed");

    free(master_secret1);
    free(master_secret2);
    free(key_block1);
    free(key_block2);
    return i;
}

static 
int test_ikev2_kdf (void)
{
    static unsigned char NiNr[] = {
	  0x36, 0x51, 0xfe, 0xf5, 0xc9, 0xc3, 0x5e, 0x93, 0xc0, 0x9a, 0x8b, 0x90,
	  0xa3, 0xf0, 0x4d, 0x59 };

    static const char GIR[] = {
          0xd0, 0x84, 0xa3, 0x01, 0x66, 0xa5, 0x0f, 0xb7, 0x32, 0x5c, 0x39, 0x60, 
	  0x87, 0x4a, 0x83, 0x94, 0x49, 0xef, 0x97, 0x41, 0xc2, 0xf4, 0xf9, 0x47, 
	  0xd0, 0x20, 0x1d, 0xd8, 0xc1, 0x26, 0x92, 0x73, 0xd7, 0x95, 0x09, 0xf3, 
	  0x7e, 0x3c, 0xa3, 0xeb, 0x4f, 0xa2, 0xfe, 0x2a, 0x28, 0x25, 0x4e, 0x28, 
	  0x9c, 0xd3, 0xf3, 0x4d, 0xad, 0x4e, 0xb4, 0xdf, 0x1a, 0x07, 0x68, 0x5a, 
	  0x4b, 0x8a, 0x94, 0xfa, 0x61, 0xe2, 0x49, 0x1f, 0x75, 0x98, 0xb3, 0xce, 
	  0x65, 0x54, 0x7f, 0xf1, 0x33, 0xb3, 0xf6, 0x3d, 0x1a, 0xc4, 0x17, 0x5e, 
	  0xaa, 0x69, 0x50, 0x33, 0xf3, 0xce, 0xdb, 0x02, 0x6a, 0x68, 0x73, 0xa3, 
	  0x64, 0x55, 0x17, 0x2a, 0x85, 0x40, 0xb8, 0xa5, 0xd2, 0x3a, 0x01, 0x43, 
	  0xbe, 0xd0, 0x39, 0x0e, 0xe4, 0x9b, 0x16, 0x82, 0x69, 0xd7, 0x5f, 0xff, 
	  0xee, 0x9f, 0xb6, 0x2b, 0xe9, 0x65, 0x99, 0x3c };

    static unsigned char GIR_new[] = { 
          0x52, 0xf0, 0x0a, 0xb1, 0x74, 0xc2, 0x5d, 0x5b, 0x71, 0x39, 0xae, 0x5f, 
	  0xf4, 0xe8, 0xe9, 0xed, 0xde, 0xe5, 0x99, 0x2d, 0x2e, 0x36, 0xad, 0xf8, 
	  0xa5, 0x59, 0xff, 0xd9, 0x0d, 0xab, 0x14, 0x42, 0xe4, 0xfb, 0xe4, 0x29, 
	  0xd3, 0x20, 0xc0, 0xf3, 0x35, 0x52, 0xa1, 0x7d, 0x15, 0x57, 0xfa, 0x41, 
	  0xea, 0x70, 0xe8, 0xfb, 0x91, 0x6c, 0x4f, 0xa2, 0x7e, 0xd5, 0x2b, 0x5f, 
	  0x8e, 0xbd, 0x84, 0x61, 0xaf, 0xa7, 0x8f, 0x11, 0x59, 0x15, 0x9a, 0x64, 
	  0x05, 0x5a, 0xc5, 0xf6, 0x31, 0x9e, 0x29, 0xc2, 0x8e, 0xae, 0x58, 0xcb, 
	  0xc6, 0x84, 0x77, 0x70, 0xf3, 0x2c, 0x3f, 0xed, 0x1d, 0x04, 0x75, 0x04, 
	  0x84, 0xf8, 0x54, 0x79, 0x0f, 0x95, 0xe9, 0xec, 0x01, 0xbc, 0x5b, 0xc4, 
	  0x61, 0xf2, 0x49, 0x66, 0x46, 0x2e, 0x35, 0x95, 0x11, 0x32, 0x93, 0x05, 
	  0x03, 0x8e, 0x94, 0xde, 0xb6, 0xdd, 0x42, 0xc2 };

    static unsigned char NiNrSPIiSPIr[] = {
          0x36, 0x51, 0xfe, 0xf5, 0xc9, 0xc3, 0x5e, 0x93, 0xc0, 0x9a, 0x8b, 0x90, 
	  0xa3, 0xf0, 0x4d, 0x59, 0x8e, 0x5c, 0x3a, 0xe5, 0x07, 0x22, 0x16, 0x84, 
	  0xb1, 0xf2, 0x01, 0xbb, 0x15, 0x5c, 0x3a, 0xcd };

    static const char SKEYSEED[] = {
          0xcd, 0x2e, 0x80, 0x50, 0x13, 0x78, 0x32, 0x24, 0x5f, 0x1d, 0xba, 0xcc,
	  0x6e, 0x4f, 0x0a, 0x92, 0xf9, 0x4d, 0x45, 0xd6 };

    static const char DKM[] = {
          0x6f, 0x1b, 0x12, 0xca, 0xd3, 0xcb, 0xe0, 0x97, 0xb3, 0x54, 0x30, 0x35, 
	  0x6d, 0x86, 0x9d, 0x54, 0xcd, 0xdb, 0x01, 0x98, 0xec, 0x85, 0x91, 0x74, 
	  0xd5, 0x3c, 0xeb, 0x92, 0xdd, 0xde, 0xdb, 0xe2, 0x43, 0x6d, 0xb6, 0x9f, 
	  0x60, 0x97, 0x7c, 0x58, 0xfa, 0x63, 0xbb, 0xb6, 0x67, 0xf8, 0xd3, 0x69, 
	  0x20, 0xb1, 0x09, 0xba, 0xae, 0x8f, 0x6c, 0x61, 0xa9, 0xac, 0x49, 0xfe, 
	  0xda, 0x01, 0x84, 0x32, 0x25, 0xd0, 0x80, 0xec, 0x55, 0x39, 0xd5, 0x88, 
	  0x1a, 0x25, 0x52, 0x1f, 0xfb, 0x2a, 0x0a, 0x91, 0x87, 0x4a, 0x9c, 0x0a, 
	  0x27, 0xfc, 0xc2, 0xd7, 0x17, 0xeb, 0x89, 0x63, 0xa9, 0xe3, 0xa8, 0x9c, 
	  0x7a, 0xb2, 0x64, 0x75, 0x72, 0x84, 0xc2, 0x8c, 0xf8, 0xc3, 0xca, 0x40, 
	  0x57, 0x6f, 0x42, 0x20, 0xb0, 0x52, 0xb1, 0xfb, 0x8e, 0x9a, 0xd6, 0x0b, 
	  0xa3, 0xc8, 0x05, 0x57, 0x32, 0x33, 0x31, 0xa8, 0xcb, 0xb8, 0x9f, 0x20 };

    static const char DKM_SA[] = {
          0x47, 0x27, 0xdc, 0x0e, 0xf9, 0x4e, 0xb3, 0x26, 0xce, 0x13, 0x1c, 0xf2, 
	  0x82, 0xfb, 0x65, 0x2f, 0xaa, 0x63, 0x8a, 0xd0, 0xdd, 0xae, 0x37, 0x86, 
	  0xa1, 0x1b, 0xcc, 0x03, 0x09, 0x87, 0x60, 0x09, 0xf8, 0xc4, 0x85, 0xde, 
	  0x01, 0x1a, 0xd9, 0x62, 0xc5, 0xb1, 0xca, 0x8a, 0x41, 0xff, 0x81, 0x45, 
	  0x44, 0x57, 0x49, 0x07, 0x9c, 0x56, 0x86, 0xe2, 0x6f, 0xfe, 0xbb, 0xc3, 
	  0x42, 0xf0, 0x69, 0x81, 0xf3, 0xda, 0x74, 0x5e, 0x11, 0xca, 0x09, 0x76, 
	  0x42, 0x4d, 0x1f, 0x8c, 0xae, 0xc6, 0x23, 0xd5, 0x9d, 0xc7, 0x18, 0x6d, 
	  0xeb, 0x20, 0xa2, 0x7b, 0x41, 0x1d, 0x1d, 0xcb, 0x70, 0xa3, 0x65, 0x44, 
	  0x0b, 0xf7, 0xde, 0x90, 0x50, 0x88, 0xb0, 0x69, 0x2e, 0x8a, 0xdd, 0xc0, 
	  0x94, 0xe1, 0x8d, 0x19, 0x39, 0xbd, 0xb6, 0x7e, 0x89, 0x79, 0x8c, 0xa6, 
	  0xb2, 0x39, 0xe2, 0xcc, 0xb8, 0x1c, 0x24, 0x09, 0xda, 0xc0, 0x10, 0x6c };

    static const char DKM_SA_DH[] = {
          0xb1, 0x09, 0xc2, 0x1a, 0xd4, 0xc0, 0x79, 0x77, 0x68, 0xc1, 0xce, 0xc9, 
	  0xe6, 0x35, 0x54, 0x68, 0x1e, 0x48, 0xf2, 0x24, 0xbc, 0xa7, 0xf2, 0x3c, 
	  0x20, 0xc4, 0xea, 0x70, 0x41, 0x98, 0x34, 0x51, 0xe9, 0xaa, 0x1d, 0x54, 
	  0x08, 0x65, 0x6c, 0x8a, 0x97, 0x5f, 0xf1, 0xb9, 0xd9, 0xa1, 0x2c, 0x75, 
	  0xff, 0xeb, 0x64, 0xbd, 0xec, 0xb3, 0x01, 0x74, 0x66, 0x4c, 0xcc, 0xb4, 
	  0xe1, 0x4f, 0x1c, 0x37, 0x7b, 0x7f, 0x6d, 0x15, 0x25, 0xaf, 0x77, 0xc7, 
	  0x09, 0x2a, 0xac, 0x3e, 0x47, 0xf9, 0x17, 0xeb, 0xae, 0x82, 0x97, 0xfb, 
	  0x55, 0x39, 0xd2, 0x00, 0x8c, 0xe8, 0x30, 0x82, 0x3a, 0x09, 0xcc, 0x19, 
	  0x73, 0x61, 0xd4, 0xa2, 0x89, 0xc7, 0x27, 0x45, 0xf6, 0xce, 0x9f, 0xef, 
	  0xe8, 0x12, 0xbe, 0x5b, 0xf5, 0x5b, 0x32, 0x00, 0xfb, 0xb8, 0x2e, 0x41, 
	  0xa4, 0xa4, 0x08, 0x77, 0xd3, 0xfe, 0x10, 0x6d, 0xb9, 0x09, 0x70, 0x7b };

    static const char SKEYSEED_REKEY[] = {
          0x3b, 0x03, 0xbc, 0xe7, 0x48, 0xc9, 0x6d, 0x5e, 0x83, 0x06, 0x91, 0x8d, 
	  0x2f, 0xf8, 0x9b, 0x68, 0xf0, 0x64, 0x8d, 0xa3 };

    int i, req_len, ret = 1;
    unsigned char *seedkey = NULL, *dkm = NULL, *seedkey_rekey = NULL, *dkm_sa = NULL, *dkm_sa_dh = NULL;
    const EVP_MD *evp_md;

    printf("\nStarting IKEv2 kdf test...");

    dkm = malloc(1024);
    dkm_sa = malloc(1024);
    dkm_sa_dh = malloc(1024);
    seedkey = malloc(1024);
    seedkey_rekey = malloc(1024);

    if (!dkm || !dkm_sa || !dkm_sa_dh || !seedkey || !seedkey_rekey) {
	printf("\n Failed to allocate memory for IKEv2");
	goto err;
    }

    evp_md = EVP_sha1();

    /* negative tests first, then KAT */
    ret = kdf_ikev2_gen(NULL, evp_md, NiNr, 16,
                        GIR, 128);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }
    evp_md = EVP_sha1();
    ret = kdf_ikev2_gen(seedkey, NULL, NiNr, 16,
                        GIR, 128);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }
    evp_md = EVP_sha1();
    ret = kdf_ikev2_gen(seedkey, evp_md, NULL, 16,
                        GIR, 128);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }
    evp_md = EVP_sha1();
    ret = kdf_ikev2_gen(seedkey, evp_md, NiNr, 0,
                        GIR, 128);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }
    evp_md = EVP_sha1();
    ret = kdf_ikev2_gen(seedkey, evp_md, NiNr, 16,
                        NULL, 128);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }
    evp_md = EVP_sha1();
    ret = kdf_ikev2_gen(seedkey, evp_md, NiNr, 16,
                        GIR, 0);
    if (!ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }


    ret = kdf_ikev2_gen(seedkey, evp_md, NiNr, 16,
                        GIR, 128);
    if (ret) {
        printf("IKEv2 failed seedkey generation");
	goto err;
    }

    i = memcmp(seedkey, SKEYSEED, 20);
    if (i != 0) {
	printf("\nKDF IKEv2 failed on seedkey compare");
	return -1;
    }

    req_len = sizeof(DKM);
    /* negative tests fist then KAT */
    ret = kdf_ikev2_dkm(NULL, req_len, evp_md, seedkey, 20,
	                NiNrSPIiSPIr, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, 0, evp_md, seedkey, 20,
	                NiNrSPIiSPIr, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, NULL, seedkey, 20,
	                NiNrSPIiSPIr, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, NULL, 20,
	                NiNrSPIiSPIr, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, seedkey, 0,
	                NiNrSPIiSPIr, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, seedkey, 20,
	                NULL, 32, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, seedkey, 20,
	                NiNrSPIiSPIr, 0, NULL, 0);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }
    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, seedkey, 20,
	                NiNrSPIiSPIr, 32, NULL, 20);
    if (!ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }


    ret = kdf_ikev2_dkm(dkm, req_len, evp_md, seedkey, 20,
	                NiNrSPIiSPIr, 32, NULL, 00);
    if (ret) {
        printf("IKEv2 failed dkm generation %d", ret);
	goto err;
    }

    i = memcmp(dkm, DKM, req_len);
    if (i != 0) {
	printf("\nKDF IKEv2 failed on dkm compare");
	return -1;
    }

    ret = kdf_ikev2_dkm(dkm_sa, req_len, evp_md, dkm, 20,
                        NiNr, 16, NULL, 0);
    if (ret) {
        printf("IKEv2 failed dkm_sa generation");
	goto err;
    }

    i = memcmp(dkm_sa, DKM_SA, req_len);
    if (i != 0) {
	printf("\nKDF IKEv2 failed on dkm_sa compare");
	return -1;
    }

    ret = kdf_ikev2_dkm(dkm_sa_dh, req_len, evp_md, dkm, 20,
                        NiNr, 16, GIR_new, 128);
    if (ret) {
        printf("IKEv2 failed dkm_sa_dh generation");
	goto err;
    }

    i = memcmp(dkm_sa_dh, DKM_SA_DH, req_len);
    if (i != 0) {
	printf("\nKDF IKEv2 failed on dkm_sa_dh compare");
	return -1;
    }

    /* negative tests fist then KAT */
    ret = kdf_ikev2_rekey(NULL, evp_md, NiNr, 16,
                          GIR_new, 128,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, NULL, NiNr, 16,
                          GIR_new, 128,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NULL, 16,
                          GIR_new, 128,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 0,
                          GIR_new, 128,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 16,
                          NULL, 128,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 16,
                          GIR_new, 0,
			  1, dkm, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 16,
                          GIR_new, 128,
			  1, NULL, 20);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }
    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 16,
                          GIR_new, 128,
			  1, dkm, 0);
    if (!ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }

    ret = kdf_ikev2_rekey(seedkey_rekey, evp_md, NiNr, 16,
                          GIR_new, 128,
			  1, dkm, 20);
    if (ret) {
        printf("IKEv2 failed seedkey rekey generation");
	goto err;
    }

    i = memcmp(seedkey_rekey, SKEYSEED_REKEY, 20);
    if (i != 0) {
	printf("\nKDF IKEv2 failed on seedkey_rekey compare");
	return -1;
    }


    printf("\n  IKEv2 KDF passed");
    ret = 0;
err:
    free(dkm);
    free(dkm_sa);
    free(dkm_sa_dh);
    free(seedkey);
    free(seedkey_rekey);

    return ret;
}

int main(int argc, char *argv[])
{
    int fips = 0;
    int err = 0;
    int ret = 0;
    BIO *bio_err = NULL;

    argv++;
    argc--;
    while (argc >= 1) {
        if (strcmp(*argv, "-fips") == 0) {
            fips = 1;
	}
        if (strcmp(*argv, "-err") == 0) {
            err = 1;
	}
        argc--;
        argv++;
    }

    if ((bio_err = BIO_new(BIO_s_file())) != NULL)
        BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (getenv("OPENSSL_DEBUG_MEMORY") != NULL) { /* if not defined, use
                                                   * compiled-in library
                                                   * defaults */
        if (!(0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))) {
            CRYPTO_malloc_debug_init();
            CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
        } else {
            /* OPENSSL_DEBUG_MEMORY=off */
            CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
        }
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if (fips) {
#ifdef OPENSSL_FIPS
        if (!FIPS_mode_set(1)) {
            ERR_load_crypto_strings();
            ERR_print_errors(BIO_new_fp(stderr, BIO_NOCLOSE));
            return -1;
        }
	printf("\nFIPS mode enabled\n");
#else
	printf("\nNot built with FIPS mode, exiting\n");
	return -1;
#endif
    }

    if (err) {
        ERR_load_crypto_strings();
    }

    if (test_snmp_kdf()) {
	printf("\nSNMP KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }
    if (err) {
	ERR_print_errors(bio_err);
    }

    if (test_srtp_kdf()) {
	printf("\nSRTP KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }

    if (err) {
	ERR_print_errors(bio_err);
    }

    if (test_ssh_kdf()) {
	printf("\nSSH KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }

    if (err) {
	ERR_print_errors(bio_err);
    }

    if (test_802_11i_kdf()) {
	printf("\n802.11i KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }

    if (err) {
	ERR_print_errors(bio_err);
    }

    if (test_tls_kdf()) {
	printf("\nTLS 1.2 KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }

    if (err) {
	ERR_print_errors(bio_err);
    }

    if (test_ikev2_kdf()) {
	printf("\nIKEv2 KDF tests have run, result = FAIL\n");
	ret = -1;
	goto err;
    }

err:
    if (err) {
	ERR_print_errors(bio_err);
    }

    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);

    printf("\nALL KDF tests completed\n");

    return ret;
}

