/*
 *      bf_test.c
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


#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <time.h>

#include <bf.h>
#include <bf/ospf.h>
#include <bf/tacacs.h>
#include <bf/tcpmd5.h>
#include <bf/isis.h>

const char ospf_md5_pre_data[] = {  0x02, 0x01, 0x00, 0x2c,  0x0a, 0xc8, 0x0f, 0x0d,   0x00, 0x00, 0x00, 0x04,  0x00, 0x00, 0x00, 0x02,
                                    0x00, 0x00, 0x00, 0x10,  0x50, 0x3f, 0xe7, 0x64,   0xff, 0xff, 0xff, 0x00,  0x00, 0x0a, 0x10, 0x01,
                                    0x00, 0x00, 0x00, 0x28,  0xac, 0x1d, 0x51, 0xfe,   0x00, 0x00, 0x00, 0x00 };
const unsigned ospf_md5_pre_data_len = 44;

const char ospf_md5_hash_data[] = { 0xf0, 0xa4, 0xc1, 0x14,  0x22, 0x5b, 0x5f, 0xe0,   0x63, 0x62, 0xef, 0x56,  0x63, 0x94, 0x65, 0xe5 };
const unsigned ospf_md5_hash_data_len = 16;


const char ospf_hmac_sha1_pre_data[] = {    0x02, 0x01, 0x00, 0x30,  0xac, 0x10, 0x00, 0x0a,   0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x02,
                                            0x00, 0x00, 0x01, 0x14,  0x54, 0xee, 0x45, 0xcc,   0xff, 0xff, 0xff, 0x00,  0x00, 0x0a, 0x12, 0x01,
                                            0x00, 0x00, 0x00, 0x28,  0xc0, 0xa8, 0x6f, 0x14,   0xc0, 0xa8, 0x6f, 0x0a,  0xac, 0x10, 0x00, 0x14 };
const unsigned ospf_hmac_sha1_pre_data_len = 48;

const char ospf_hmac_sha1_hash_data[] = {   0xfc, 0x87, 0x30, 0x31,  0x43, 0xfb, 0xde, 0x2e,   0xce, 0xb7, 0xf3, 0xcf,  0x38, 0x1f, 0xc5, 0x19,
                                            0xac, 0x03, 0x8a, 0xdd };
const unsigned ospf_hmac_sha1_hash_data_len = 20;


int test_ospf() {
    bf_state_t *state;
    bf_error error;
    char *secret;
    clock_t start, end;
    float seconds;
    
    printf("Testing MD5\n");
    
    if((error = ospf_bf_md5_state_new(&state)) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    //~ bf_set_wordlist(state, "/tmp/wordlist");
    //~ bf_set_mode(state, BF_WORDLIST);
    if((error = bf_set_pre_data(state, ospf_md5_pre_data, ospf_md5_pre_data_len)) > 0) {
        printf("Can't set pre data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = bf_set_hash_data(state, ospf_md5_hash_data, ospf_md5_hash_data_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    start = clock();
    if((error = bf_start(state)) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    while((error = bf_check_finished(state))) {
        usleep(100);
    }
    end = clock();

    if((error = bf_get_secret(state, &secret)) > 0) { 
        printf("\e[1;31mNo password found!\e[0m\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\e[1;32mFound password '%s' in %f seconds\e[0m\n", secret, seconds);
    }
    
    bf_state_delete(state);
    
    printf("Testing HMAC-SHA1\n");
    
    if((error = ospf_bf_hmac_sha1_state_new(&state)) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    //~ bf_set_wordlist(state, "/tmp/wordlist");
    //~ bf_set_mode(state, BF_WORDLIST);
    if((error = bf_set_pre_data(state, ospf_hmac_sha1_pre_data, ospf_hmac_sha1_pre_data_len)) > 0) {
        printf("Can't set pre data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = bf_set_hash_data(state, ospf_hmac_sha1_hash_data, ospf_hmac_sha1_hash_data_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    start = clock();
    if((error = bf_start(state)) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    while((error = bf_check_finished(state))) {
        usleep(100);
    }
    end = clock();
    
    if((error = bf_get_secret(state, &secret)) > 0) { 
        printf("\e[1;31mNo password found!\e[0m\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\e[1;32mFound password '%s' in %f seconds\e[0m\n", secret, seconds);
    }
    
    bf_state_delete(state);
    
    return 0;
}

const char tacacs_pre_data[] = {    0x6d, 0x0e, 0x16, 0x31 };
const unsigned tacacs_pre_data_len = 4;

const char tacacs_hash_data[] = {   0xc0, 0x06 };
const unsigned tacacs_hash_data_len = 2;

const char tacacs_ciphertext[] = {  0xdb, 0x7c, 0x01, 0xe7,  0x74, 0x99 };
const unsigned tacacs_ciphertext_len = 6;

int test_tacacs() {
    bf_state_t *state;
    bf_error error;
    char *secret;
    clock_t start, end;
    float seconds;
    
    if((error = tacacs_bf_state_new(&state)) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    if((error = bf_set_pre_data(state, tacacs_pre_data, tacacs_pre_data_len)) > 0) {
        printf("Can't set pre data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = bf_set_hash_data(state, tacacs_hash_data, tacacs_hash_data_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = tacacs_bf_set_ciphertext(state, tacacs_ciphertext, tacacs_ciphertext_len)) > 0) {
        printf("Can't set ciphertext: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    start = clock();
    if((error = bf_start(state)) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    while((error = bf_check_finished(state))) {
        usleep(100);
    }
    end = clock();
    
    if((error = bf_get_secret(state, &secret)) > 0) { 
        printf("\e[1;31mNo password found!\e[0m\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\e[1;32mFound password '%s' in %f seconds\e[0m\n", secret, seconds);
    }
    
    bf_state_delete(state);
    return 0;
}

const char tcpmd5_pre_data[] = {    0x45, 0xc0, 0x00, 0x40,  0x24, 0xb0, 0x40, 0x00,   0x01, 0x06, 0x40, 0x45,  0x0a, 0x00, 0x00, 0x01,
                                    0x0a, 0x00, 0x00, 0x03,  0xcd, 0xda, 0x00, 0xb3,   0xd8, 0x31, 0x4c, 0xd9,  0x00, 0x00, 0x00, 0x00,
                                    0xb0, 0x02, 0x40, 0x00,  0x28, 0x3a, 0x00, 0x00,   0x02, 0x04, 0x05, 0xa0,  0x13, 0x12, 0x99, 0x36,
                                    0xbb, 0x89, 0xb7, 0x78,  0xe5, 0xdf, 0x4f, 0xec,   0x16, 0x57, 0x8a, 0x55,  0xe2, 0x8b, 0x00, 0x00 };
const unsigned tcpmd5_pre_data_len = 64;

const char tcpmd5_hash_data[] = {   0x99, 0x36, 0xbb, 0x89,  0xb7, 0x78, 0xe5, 0xdf,   0x4f, 0xec, 0x16, 0x57,  0x8a, 0x55, 0xe2, 0x8b };
const unsigned tcpmd5_hash_data_len = 16;

int test_tcpmd5() {
    bf_state_t *state;
    bf_error error;
    char *secret;
    clock_t start, end;
    float seconds;
    
    if((error = tcpmd5_bf_state_new(&state)) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    bf_set_wordlist(state, "/tmp/wordlist");
    bf_set_mode(state, BF_WORDLIST);
    if((error = bf_set_pre_data(state, tcpmd5_pre_data, tcpmd5_pre_data_len)) > 0) {
        printf("Can't set pre data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = bf_set_hash_data(state, tcpmd5_hash_data, tcpmd5_hash_data_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    start = clock();
    if((error = bf_start(state)) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    while((error = bf_check_finished(state))) {
        usleep(100);
    }
    end = clock();
    
    if((error = bf_get_secret(state, &secret)) > 0) { 
        printf("\e[1;31mNo password found!\e[0m\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\e[1;32mFound password '%s' in %f seconds\e[0m\n", secret, seconds);
    }
    
    bf_state_delete(state);
    return 0;
}

const char isis_hash_data[] = { 0x50, 0x27, 0xb8, 0xd3,  0x7e, 0x6c, 0xe0, 0xbb,   0x4e, 0x92, 0x91, 0x0f,  0x5c, 0x2b, 0x95, 0x7b };
const unsigned isis_hash_data_len = 16;

const char isis_pdu[] = {       0x83, 0x1b, 0x01, 0x00,  0x12, 0x01, 0x00, 0x00,   0x00, 0x4d, 0x00, 0x00,  0x6c, 0x6f, 0x6b, 0x69,
                                0x34, 0x75, 0x01, 0x00,  0x00, 0x00, 0x00, 0x03,   0x00, 0x00, 0x01, 0x0a,  0x11, 0x36, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x02, 0x17,
                                0x00, 0x00, 0x80, 0x80,  0x80, 0x6c, 0x6f, 0x6b,   0x69, 0x34, 0x75, 0x00,  0x00, 0x80, 0x80, 0x80,
                                0x00, 0x03, 0x00, 0x04,  0x00, 0x05, 0x00, 0x03,   0x04, 0x0a, 0x80, 0x80,  0x80};
const unsigned isis_pdu_len = 77;

int test_isis() {
    bf_state_t *state;
    bf_error error;
    char *secret;
    clock_t start, end;
    float seconds;
    
    if((error = isis_bf_hmac_md5_state_new(&state)) > 0) {
        printf("Can't init state: %d\n", error);
        return 1;
    }
    bf_set_wordlist(state, "/tmp/wordlist");
    bf_set_mode(state, BF_WORDLIST);
    if((error = bf_set_pre_data(state, isis_pdu, isis_pdu_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    if((error = bf_set_hash_data(state, isis_hash_data, isis_hash_data_len)) > 0) {
        printf("Can't set hash data: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    start = clock();
    if((error = bf_start(state)) > 0) {
        printf("Can't start bruteforce: %d\n", error);
        bf_state_delete(state);
        return 1;
    }
    while((error = bf_check_finished(state))) {
        usleep(100);
    }
    end = clock();
    
    if((error = bf_get_secret(state, &secret)) > 0) { 
        printf("\e[1;31mNo password found!\e[0m\n");
    } else {
        seconds = (double)(end - start) / CLOCKS_PER_SEC;
        printf("\e[1;32mFound password '%s' in %f seconds\e[0m\n", secret, seconds);
    }
    
    bf_state_delete(state);
    return 0;
}

int main(int argc, char **argv)
{
	int ret;
    
    printf("*** Running OSPF test\n");
    ret = test_ospf();
    printf("*** OSPF test %s\n\n", ret ? "FAILED" : "PASSED");
    
    printf("*** Running TACACS+ test\n");
    ret = test_tacacs();
    printf("*** TACACS+ test %s\n\n", ret ? "FAILED" : "PASSED");
    
    printf("*** Running TCPMD5 test\n");
    ret = test_tcpmd5();
    printf("*** TCPMD5 test %s\n\n", ret ? "FAILED" : "PASSED");
    
    printf("*** Running ISIS test\n");
    ret = test_isis();
    printf("*** ISIS test %s\n\n", ret ? "FAILED" : "PASSED");
    
	return 0;
}

