/*------------------------------------------------------------------
 * kdf/kdf_ssh.c - Key Derivation Function for SSH
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
#include <openssl/kdf.h>
#include <openssl/sha.h>
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

/*! @brief kdf_ssh - In compliance with SP800-135 and RFC 4253, calculate
                     IVs and keys based on the input values.

@latexonly
\begin{verbatim}
      K = shared secret
      H = hash value
      N = [L/Hash_Length]
      X is a character, such as A, B, C, D, E or F, depending on the type
        of key desired.


      NIST SP 800-135, Revision 1
      K1 = HASH (K || H || X || session_id), where session_id
      is a unique identifier for a SSH connection.
      K2 = HASH (K || H || K1)
      K3 = HASH (K || H || K1 || K2)

      KN = HASH (K || H || K1 || K2 ||...|| K(N-1))
      KEY = the L left most bits of (K1 || K2 ||... KN) 

\end{verbatim}
@endlatexonly

      @param evp_md - the SHA digest to be used
      @param id - character such as A, B, C....
      @param need - bytes needed for key
      @param shared_secret - pointer to secret(K)
      @param ss_len - length of shared_secret(in bytes)
      @param session_id - session id, usually H from the first key exchange
      @param session_id_len - length of session_id(in bytes)
      @param hash - pointer to hash (H)
      @param hash_len - length of hash(in bytes)
      @param digest - pointer to key output, always length of "need" bytes.

      @return - length of key or -1 for error  

 */
int kdf_ssh(const EVP_MD *evp_md, int id, unsigned int need, char *shared_secret, 
            int ss_len, char *session_id, int session_id_len, char *hash, 
	    int hash_len, unsigned char *digest)
{
    char c = id;
    EVP_MD_CTX md;
    unsigned int mdsz, have;

    if (!evp_md || !id || !need || !shared_secret || !ss_len || !session_id ||
        !session_id_len || !hash || !hash_len || !digest) {
        KDFerr(KDF_F_KDF_SSH, KDF_R_INPUT_PARAMETER_ERROR);
        return -1;
    }

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        /* since the digest is already chosen, need to convert for FIPS */
        evp_md = FIPS_get_digestbynid(evp_md->type);
	if (!evp_md) {
            KDFerr(KDF_F_KDF_SSH, KDF_R_BAD_DIGEST);
            return -1;
        }
        return FIPS_kdf_ssh(evp_md, id, need, shared_secret, ss_len, session_id, 
	                    session_id_len, hash, hash_len, digest);
    }
#endif

    mdsz = EVP_MD_size(evp_md);
    switch(evp_md->type) {
        case NID_sha1:
        case NID_sha224:
        case NID_sha256:
        case NID_sha384:
        case NID_sha512:
	    EVP_MD_CTX_init(&md);
	    /* K1 = HASH(K || H || "A" || session_id) */
	    if (!EVP_DigestInit_ex(&md, evp_md, NULL)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, shared_secret, ss_len)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, hash, hash_len)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, &c, 1)) {
	        goto err;
	    }
	    if (!EVP_DigestUpdate(&md, session_id, session_id_len)) {
	        goto err;
	    }
	    if (!EVP_DigestFinal_ex(&md, digest, NULL)) {
	        goto err;
	    }

	    /*
	     * expand key:
	     * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	     * Key = K1 || K2 || ... || Kn
	     */
	    for (have = mdsz; need > have; have += mdsz) {
	        if (!EVP_DigestInit_ex(&md, evp_md, NULL)) {
	            goto err;
                 }
		 if (!EVP_DigestUpdate(&md, shared_secret, ss_len)) {
 		     goto err;
                 }
		 if (!EVP_DigestUpdate(&md, hash, hash_len)) {
 		     goto err;
                 }
		 if (!EVP_DigestUpdate(&md, digest, have)) {
 		     goto err;
                 }
		 if (!EVP_DigestFinal_ex(&md, digest + have, NULL)) {
 		     goto err;
                 }
	    }
	    break;
        default:
            KDFerr(KDF_F_KDF_SSH, KDF_R_BAD_DIGEST);
	    return -1;
	    break;
    }    
err:
    EVP_MD_CTX_cleanup(&md);
    return 0;
}
