/*
 *      algos.h
 * 
 *      Copyright 2015 Daniel Mende <dmende@ernw.de>
 */

/*
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of the  nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ALGOS_H_
#define _ALGOS_H_

#include <config.h>

#ifdef HAVE_LIBCRYPTO

# include <openssl/md5.h>
# include <openssl/sha.h>
# include <openssl/hmac.h>
# include <openssl/evp.h>

# define HMAC_MD5(a, b, c, d, e, f) HMAC(EVP_md5(), (a), (b), (c), (d), (e), (f))
# define HMAC_SHA1(a, b, c, d, e, f) HMAC(EVP_sha1(), (a), (b), (c), (d), (e), (f))

#else

# include <algos/hmac_md5.h>
# include <algos/sha1.h>
# include <algos/sha2.h>
# include <algos/hmac_sha2.h>

# define HMAC_MD5(a, b, c, d, e, f) hmac_md5((c), (d), (a), (b), (e))
# define HMAC_SHA1(a, b, c, d, e, f) { sha1nfo ctx; sha1_initHmac(&ctx, (a), (b)); sha1_write(&ctx, (c), (d)); memcpy((e), sha1_resultHmac(&ctx), SHA_DIGEST_LENGTH); }

#endif


#endif
