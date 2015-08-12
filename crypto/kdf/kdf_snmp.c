/*------------------------------------------------------------------
 * kdf/kdf_snmp.c - Key Derivation Function for SNMP
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
#include "cryptlib.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*! @brief kdf_snmp() - In compliance with SP800-135 and RFC2574, calculate
                        a master key using the engine ID and password.
  
@latexonly
\begin{verbatim}
  Denote engineLength and passwordlen to be the lengths (in bytes) of an
  snmpEngineID and a password, respectively.

  Let N = (1024*1024)/passwordlen

  Expanded_password = the leftmost 1048576 bytes of the string of N
  repetitions of the password.

  Derived_password = SHA-1 (Expanded_password). The Derived_password
  is the output of hashing the Expanded_password by SHA-1.

  Let Shared_key to be the key that the user shares with the authoritative
  SNMP engine with ID snmpEngineID. The Shared_key is generated as follow:

  Shared_key = SHA-1(Derived_password || snmpEngineID || Derived_password). 

\end{verbatim}
@endlatexonly
      @param e_id - engine ID(snmpEngineID)
      @param e_len - engineID length
      @param password - password
      @param pw_len - password length
      @param digest - pointer to key output, always length of 20 bytes.
  
      @return - length of key or -1 for error
  
 */
int kdf_snmp(unsigned char *e_id, int e_len, const char *password, 
             int pw_len, unsigned char *digest)
{
    EVP_MD_CTX md;
    int len;
    unsigned int md_len = -1;

    if (!e_id || !e_len || !password || !pw_len || !digest) {
        KDFerr(KDF_F_KDF_SNMP, KDF_R_INPUT_PARAMETER_ERROR);
        return -1;
    }
#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        return FIPS_kdf_snmp(e_id, e_len, password, pw_len, digest);
    }
#endif

    EVP_MD_CTX_init(&md);
    if (!EVP_DigestInit_ex(&md, EVP_sha1(), NULL)) {
	goto err;
    }
    for (len = 0; len < PASSWORD_HASH_AMOUNT - pw_len; len += pw_len ) {
        if (!EVP_DigestUpdate(&md, password, pw_len)) {
	    goto err;
        }
    }
    if (!EVP_DigestUpdate(&md, password, PASSWORD_HASH_AMOUNT - len)) {
	goto err;
    }
    if (!EVP_DigestFinal_ex(&md, digest, &md_len)) {
        goto err;
    }

    if (!EVP_DigestInit_ex(&md, EVP_sha1(), NULL)) {
        goto err;
    }
    if (!EVP_DigestUpdate(&md, digest, SHA_DIGEST_LENGTH)) {
        goto err;
    }
    if (!EVP_DigestUpdate(&md, e_id, e_len)) {
        goto err;
    }
    if (!EVP_DigestUpdate(&md, digest, SHA_DIGEST_LENGTH)) {
        goto err;
    }
    if (!EVP_DigestFinal_ex(&md, digest, &md_len)) {
        goto err;
    }

err:
    EVP_MD_CTX_cleanup(&md);
    return md_len;
}
