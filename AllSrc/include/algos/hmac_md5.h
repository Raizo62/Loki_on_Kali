/*
 * hmac_md5.h
 */

#ifndef hmac_md5_INCLUDED
#define hmac_md5_INCLUDED

#include <algos/md5.h>

#ifdef __cplusplus
extern "C" 
{
#endif

void hmac_md5(const unsigned char* text, int text_len, const unsigned char* key, int key_len, md5_byte_t* digest);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif /* hmac_md5_INCLUDED */
