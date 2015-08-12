/*------------------------------------------------------------------
 * kdf/kdf_srtp.c - Key Derivation Function for SRTP
 *
 * This product contains software written by:
 * Barry Fussell (bfussell@cisco.com)
 * Cisco Systems, March 2015
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
#include "cryptlib.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*! @brief kdf_srtp - In compliance with SP800-135 and RFC3711, calculate
                      various keys defined by label using a master key,
                      master salt, kdr(if non-zero) and index.


@latexonly
\begin{verbatim}
      Denote the cryptographic key (encryption key, cipher salt or 
      authentication key(HMAC key), etc) to be derived as K. The
      length of K is denoted by L. Below is a description of the KDF.

       master_salt: a random non-secret value.
       kdr: the key derivation rate. kdr is a number from the set 
            factor of 2.
       index: a 48-bit value in RTP or a 32-bit value in RTCP. 
              See Sections 3.2.1 and 4.3.2 of RFC 3711 for details.
       A function, DIV, is defined as followed:

         a and x are non-negative integers.
         a DIV x =  a | x (a DIV x) is represented as a bit string whose 
         length (in bits) is the same as a.

       label: an 8-bit value represented by two hexadecimal numbers from
              the set of {0x00,0x01, 0x02, 0x03, 0x04, 0x05}. In the future, 
              this set might also include any or all of the values 0x06, 
              0x07, 0xff.
       key_id = label || (index DIV kdr) 

\end{verbatim}
@endlatexonly

      @param cipher - AES cipher
      @param km - pointer to master key
      @param ms - pointer to master salt
      @param kdr - pointer to key derivation rate
      @param idx - pointer to index
      @param label - 8-bit label
      @param buffer - buffer for output

      @return - 0 on pass, -1 fail
 */
int kdf_srtp(const EVP_CIPHER *cipher, char *km, char *ms, char *kdr, 
             char *idx, int label, char *buffer)
{
    EVP_CIPHER_CTX ctx;
    int outl, i, idx_len = 0, o_len = 0, ms_len = 0;
    unsigned char buf[32];
    char iv[KDF_SRTP_IV_LEN];
    char salt[KDF_SRTP_SALT_LEN + 2];
    char master_salt[KDF_SRTP_IV_LEN];
    BN_CTX *bn_ctx;
    BIGNUM *bn_idx = NULL, *bn_kdr = NULL, *bn_salt = NULL;
    int ret, iv_len = KDF_SRTP_IV_LEN, rv = -1;

    
    if (!cipher || !km || !ms || !buffer) {
        KDFerr(KDF_F_KDF_SRTP, KDF_R_INPUT_PARAMETER_ERROR);
        return rv;
    }
    if (label > 5) {
        KDFerr(KDF_F_KDF_SRTP, KDF_R_INPUT_PARAMETER_ERROR);
        return rv;
    }

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        /* since the cipher is already chosen, need to convert for FIPS */
        cipher = FIPS_get_cipherbynid(cipher->nid);
	if (!cipher) {
            KDFerr(KDF_F_KDF_SRTP, KDF_R_BAD_CIPHER);
            return rv;
        }
        return FIPS_kdf_srtp(cipher, km, ms, kdr, 
                             idx, label, buffer);
    }
#endif

    ms_len = KDF_SRTP_SALT_LEN;

    /* get label-specific lengths */
    switch (label)
    {
    case 0:
        idx_len = KDF_SRTP_IDX_LEN;
	o_len = cipher->key_len;
	break;
    case 1:
        idx_len = KDF_SRTP_IDX_LEN;
	o_len = KDF_SRTP_AUTH_KEY_LEN;
	break;
    case 2:
        idx_len = KDF_SRTP_IDX_LEN;
	o_len = KDF_SRTP_SALT_KEY_LEN;
	break;
    case 3:
        idx_len = KDF_SRTCP_IDX_LEN;
	o_len = cipher->key_len;
	break;
    case 4:
        idx_len = KDF_SRTCP_IDX_LEN;
	o_len = KDF_SRTCP_AUTH_KEY_LEN;
	break;
    case 5:
        idx_len = KDF_SRTCP_IDX_LEN;
	o_len = KDF_SRTCP_SALT_KEY_LEN;
	break;
    default:
        KDFerr(KDF_F_KDF_SRTP, KDF_R_INPUT_PARAMETER_ERROR);
        return rv;
    }

    /* set up a couple of work areas for the final logic on the salt */
    memset(iv, 0, KDF_SRTP_IV_LEN);
    memset(master_salt, 0, KDF_SRTP_IV_LEN);
    memcpy(master_salt, ms, ms_len);

    if ((bn_ctx = BN_CTX_new()) == NULL) {
        KDFerr(KDF_F_KDF_SRTP, KDF_R_BN_CTX_ERR);
        return rv;
    }

    /* gather some bignums for some math */
    BN_CTX_start(bn_ctx);
    bn_idx = BN_CTX_get(bn_ctx);
    bn_kdr = BN_CTX_get(bn_ctx);
    bn_salt = BN_CTX_get(bn_ctx);
    if (!bn_idx || !bn_kdr || !bn_salt) {
        KDFerr(KDF_F_KDF_SRTP, KDF_R_BN_GET_ERR);
	if (bn_idx)
	    BN_free(bn_idx);
	if (bn_kdr)
	    BN_free(bn_kdr);
	if (bn_salt)
	    BN_free(bn_salt);
	BN_CTX_end(bn_ctx);
	return rv;
    }

    /* if either are NULL, then idx and kdr are not in play */
    if (idx && kdr) {
        bn_idx = BN_bin2bn((unsigned char *)idx, idx_len, NULL);
	bn_kdr = BN_bin2bn((unsigned char *)kdr, KDF_SRTP_KDR_LEN, NULL);
    } else {
        /* default kdr bignum to zero */
	BN_zero(bn_kdr);
    }

    /* if kdr exists, but is zero, idx and kdr are not in play */
    if (!BN_is_zero(bn_kdr)) {
        ret = BN_div(bn_salt, NULL, bn_idx, bn_kdr, bn_ctx);
	if (!ret) {
	    goto err;
        }
        iv_len = BN_bn2bin(bn_salt, (unsigned char *)iv);
        for (i=1; i<=iv_len; i++) {
            master_salt[ms_len-i] ^= iv[iv_len-i];
        }
    }

    /* take the munged up salt from above and add the label */
    memset(salt, 0 , KDF_SRTP_SALT_LEN + 2);
    memcpy(salt, master_salt, ms_len);
    salt[((KDF_SRTP_SALT_LEN-1)-idx_len)] ^= label++;

    /* perform the AES encryption on the master key and derived salt */
    memset(buf, 0, o_len);
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_EncryptInit_ex(&ctx, cipher, NULL, (unsigned char *)km, (unsigned char *)salt) <= 0) {
        goto err;
    } 
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    if (EVP_EncryptUpdate(&ctx, (unsigned char *)buffer, &outl, buf, o_len) <= 0) {
        goto err;
    }
    if (EVP_EncryptFinal_ex(&ctx, (unsigned char *)buffer, &outl) <= 0) {
        goto err;
    }

    rv = 0;
err:
    OPENSSL_cleanse(iv, KDF_SRTP_IV_LEN);
    OPENSSL_cleanse(salt, KDF_SRTP_SALT_LEN + 2);
    OPENSSL_cleanse(master_salt, KDF_SRTP_IV_LEN);
    EVP_CIPHER_CTX_cleanup(&ctx);
    BN_free(bn_idx);
    BN_free(bn_kdr);
    BN_free(bn_salt);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return rv;
}
