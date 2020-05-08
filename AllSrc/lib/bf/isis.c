/*
 *      isis.c
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

#include <stdlib.h>
#include <string.h>

#include <bf/isis.h>

const char isis_apad[] = {  0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3,
                            0x87, 0x8F, 0xE1, 0xF3 };

static void isis_bf_hmac_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    isis_hmac_data_t *data = (isis_hmac_data_t *) proto_data;
    data->pdu = pre_hash_data;
    data->pdu_len = pre_hash_data_len;
}

static int isis_bf_hmac_md5_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    isis_hmac_data_t *data = (isis_hmac_data_t *) proto_data;
    unsigned char digest[MD5_DIGEST_LENGTH];
    
    unsigned len;
    HMAC_MD5(secret, strlen(secret), data->pdu, data->pdu_len, digest, &len);

    if(!memcmp(hash_data, digest, MD5_DIGEST_LENGTH))
        return 1;
    return 0;
}

bf_error isis_bf_hmac_md5_state_new(bf_state_t **state) {
    bf_error error;
    isis_hmac_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(isis_hmac_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    proto_data->pdu = NULL;
    proto_data->pdu_len = 0;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, isis_bf_hmac_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, isis_bf_hmac_md5_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}

static int isis_bf_hmac_sha1_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    isis_hmac_data_t *data = (isis_hmac_data_t *) proto_data;
    SHA_CTX ctx;
    unsigned char result[SHA_DIGEST_LENGTH];
    unsigned char key[SHA_DIGEST_LENGTH];
#ifdef HAVE_LIBCRYPTO
    HMAC_CTX ctx2;
#else
    sha1nfo ctx2;
#endif
    unsigned len = strlen(secret);
    
    /* key setup */
    if(len < SHA_DIGEST_LENGTH) {
        memcpy(key, secret, len);
        memset(key + len, 0, SHA_DIGEST_LENGTH - len);
    } else if(len == SHA_DIGEST_LENGTH) {
        memcpy(key, secret, SHA_DIGEST_LENGTH);
    } else {
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, secret, len);
        SHA1_Final(key, &ctx);
    }
    
#ifdef HAVE_LIBCRYPTO
    HMAC_CTX_init(&ctx2);
    HMAC_Init(&ctx2, key, SHA_DIGEST_LENGTH, EVP_sha1());
    HMAC_Update(&ctx2, data->pdu, data->pdu_len);
    HMAC_Update(&ctx2, isis_apad, SHA_DIGEST_LENGTH);
    HMAC_Final(&ctx2, result, &len);
#else
    sha1_initHmac(&ctx2, key, SHA_DIGEST_LENGTH);
    sha1_write(&ctx2, data->pdu, data->pdu_len);
    sha1_write(&ctx2, isis_apad, SHA_DIGEST_LENGTH);
    memcpy(result, sha1_resultHmac(&ctx2), SHA_DIGEST_LENGTH);
#endif

    if(!memcmp(hash_data, result, SHA_DIGEST_LENGTH))
        return 1;
    return 0;
}

bf_error isis_bf_hmac_sha1_state_new(bf_state_t **state) {
    bf_error error;
    isis_hmac_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(isis_hmac_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    proto_data->pdu = NULL;
    proto_data->pdu_len = 0;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, isis_bf_hmac_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, isis_bf_hmac_sha1_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}

static int isis_bf_hmac_sha256_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    isis_hmac_data_t *data = (isis_hmac_data_t *) proto_data;
    SHA256_CTX ctx;
    unsigned char result[SHA256_DIGEST_LENGTH];
    unsigned char key[SHA256_DIGEST_LENGTH];
#ifdef HAVE_LIBCRYPTO
    HMAC_CTX ctx2;
#else
    hmac_sha256_ctx ctx2;
#endif
    unsigned len = strlen(secret);
    
    /* key setup */
    if(len < SHA256_DIGEST_LENGTH) {
        memcpy(key, secret, len);
        memset(key + len, 0, SHA256_DIGEST_LENGTH - len);
    } else if(len == SHA256_DIGEST_LENGTH) {
        memcpy(key, secret, SHA256_DIGEST_LENGTH);
    } else {
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, secret, len);
        SHA256_Final(key, &ctx);
    }
    
#ifdef HAVE_LIBCRYPTO
    HMAC_CTX_init(&ctx2);
    HMAC_Init(&ctx2, key, SHA256_DIGEST_LENGTH, EVP_sha256());
    HMAC_Update(&ctx2, data->pdu, data->pdu_len);
    HMAC_Update(&ctx2, isis_apad, SHA256_DIGEST_LENGTH);
    HMAC_Final(&ctx2, result, &len);
#else
    hmac_sha256_init(&ctx2, key, SHA256_DIGEST_LENGTH);
    hmac_sha256_update(&ctx2, data->pdu, data->pdu_len);
    hmac_sha256_update(&ctx2, isis_apad, SHA256_DIGEST_LENGTH);
    hmac_sha256_final(&ctx2, result, SHA256_DIGEST_LENGTH);
#endif

    if(!memcmp(hash_data, result, SHA_DIGEST_LENGTH))
        return 1;
    return 0;
}

bf_error isis_bf_hmac_sha256_state_new(bf_state_t **state) {
    bf_error error;
    isis_hmac_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(isis_hmac_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    proto_data->pdu = NULL;
    proto_data->pdu_len = 0;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, isis_bf_hmac_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, isis_bf_hmac_sha256_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}
