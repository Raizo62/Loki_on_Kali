/*
 *      tacacs.c
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

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <bf/tacacs.h>

static void tacacs_bf_pre_hash_func(void *proto_data, const char *pre_hash_data, unsigned pre_hash_data_len) {
    tacacs_data_t *data = (tacacs_data_t *) proto_data;
    MD5_Init(&data->base);
    MD5_Update(&data->base, pre_hash_data, pre_hash_data_len);
}

static int tacacs_bf_hash_func(void *proto_data, const char *secret, const char *hash_data, unsigned hash_data_len) {
    tacacs_data_t *data = (tacacs_data_t *) proto_data;
    MD5_CTX cur;
    unsigned char digest[MD5_DIGEST_LENGTH];
    int i;
    unsigned char status, flags;
    unsigned short server_msg_len, data_len;
    unsigned char cleartext[MD5_DIGEST_LENGTH];
    
    memcpy((void *) &cur, &data->base, sizeof(MD5_CTX));
    MD5_Update(&cur, secret, strlen(secret));
    MD5_Update(&cur, hash_data, hash_data_len);
    MD5_Final(digest, &cur);

#if 0
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        cleartext[i] = data->ciphertext[i] ^ digest[i];
    }
#else
    cleartext[0] = data->ciphertext[0] ^ digest[0];
    cleartext[1] = data->ciphertext[1] ^ digest[1];
    cleartext[2] = data->ciphertext[2] ^ digest[2];
    cleartext[3] = data->ciphertext[3] ^ digest[3];
    cleartext[4] = data->ciphertext[4] ^ digest[4];
    cleartext[5] = data->ciphertext[5] ^ digest[5];
    cleartext[6] = data->ciphertext[6] ^ digest[6];
    cleartext[7] = data->ciphertext[7] ^ digest[7];
    cleartext[8] = data->ciphertext[8] ^ digest[8];
    cleartext[9] = data->ciphertext[9] ^ digest[9];
    cleartext[10] = data->ciphertext[10] ^ digest[10];
    cleartext[11] = data->ciphertext[11] ^ digest[11];
    cleartext[12] = data->ciphertext[12] ^ digest[12];
    cleartext[13] = data->ciphertext[13] ^ digest[13];
    cleartext[14] = data->ciphertext[14] ^ digest[13];
    cleartext[15] = data->ciphertext[15] ^ digest[15];
#endif
    
    status = cleartext[0];
    flags = cleartext[1];
    server_msg_len = ntohs(*((unsigned short *) &cleartext[2]));
    data_len = ntohs(*((unsigned short *) &cleartext[4]));
    
    if( ((status >= 0x01 && status <= 0x07) || status == 0x21) && 
        (flags == 0x01 || flags == 0x00) &&
        (6 + server_msg_len + data_len == data->ciphertext_len)) {            
            return 1;
    }
    return 0;
}

bf_error tacacs_bf_state_new(bf_state_t **state) {
    bf_error error;
    tacacs_data_t *proto_data;
    
    if((error = bf_state_new(state)) > 0)
        return error;
    
    proto_data = malloc(sizeof(tacacs_data_t));
    if(proto_data == NULL)
        return BF_ERR_NO_MEM;
    proto_data->ciphertext = NULL;
    proto_data->ciphertext_len = 0;
    if((error = bf_set_proto_data(*state, (void *) proto_data, NULL)) > 0) {
        free(proto_data);
        return error;
    }
    if((error = bf_set_pre_hash_func(*state, tacacs_bf_pre_hash_func)) > 0)
        return error;
    if((error = bf_set_hash_func(*state, tacacs_bf_hash_func)) > 0)
        return error;
    return BF_SUCCESS;
}

bf_error tacacs_bf_set_ciphertext(bf_state_t *state, const char *ciphertext, unsigned ciphertext_len) {
    tacacs_data_t *data;
    BF_CHECK_NULL(state);
    BF_CHECK_RUNNING(state);
    data = (tacacs_data_t *) state->proto_data;
    data->ciphertext = ciphertext;
    data->ciphertext_len = ciphertext_len;
    return BF_SUCCESS;
}

bf_error tacacs_bf_get_ciphertext(bf_state_t *state, const char **ciphertext, unsigned *ciphertext_len) {
    tacacs_data_t *data;
    BF_CHECK_NULL(state);
    BF_CHECK_NULL(ciphertext);
    BF_CHECK_NULL(ciphertext_len);
    data = (tacacs_data_t *) state->proto_data;
    *ciphertext = data->ciphertext;
    *ciphertext_len = data->ciphertext_len;
    return BF_SUCCESS;
}

