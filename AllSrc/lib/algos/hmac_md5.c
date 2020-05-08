/*
** RFC2104
** Function: hmac_md5
*/

#include <string.h>
#include <algos/hmac_md5.h>

// HMAC := H(K XOR opad, H(K XOR ipad, text))

void
hmac_md5(text, text_len, key, key_len, digest)
const unsigned char*  text;          /* pointer to data stream */
int             text_len;            /* length of data stream */
const unsigned char*  key;           /* pointer to authentication key */
int             key_len;             /* length of authentication key */
md5_byte_t*     digest;              /* caller digest to be filled in */

{
        md5_state_t context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;
        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

                md5_state_t      tctx;

                md5_init(&tctx);
                md5_append(&tctx, (const md5_byte_t *) key, key_len);
                md5_finish(&tctx, tk);

                key = tk;
                key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        memset( k_ipad, 0, sizeof k_ipad);
        memset( k_opad, 0, sizeof k_opad);
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        md5_init(&context);                   /* init context for 1st
                                              * pass */
        md5_append(&context, k_ipad, 64);     /* start with inner pad */
        md5_append(&context, text, text_len); /* then text of datagram */
        md5_finish(&context, digest);         /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        md5_init(&context);                   /* init context for 2nd
                                              * pass */
        md5_append(&context, k_opad, 64);     /* start with outer pad */
        md5_append(&context, digest, 16);     /* then results of 1st
                                              * hash */
        md5_finish(&context, digest);          /* finish up 2nd pass */
}

