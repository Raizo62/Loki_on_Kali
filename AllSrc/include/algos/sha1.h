#ifndef _SHA1_C_
#define _SHA1_C_

#include <stdint.h>

#include <config.h>

#ifdef WORDS_BIGENDIAN
# define SHA_BIG_ENDIAN
#endif

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

/*libcrypto compability */
#define SHA_DIGEST_LENGTH 20
#define SHA_CTX sha1nfo
#define SHA1_Init(x) sha1_init((x))
#define SHA1_Update(x, y, z) sha1_write((x), (y), (z))
#define SHA1_Final(x, y) memcpy((x), sha1_result((y)), SHA_DIGEST_LENGTH)

typedef struct sha1nfo {
	uint32_t buffer[BLOCK_LENGTH/4];
	uint32_t state[HASH_LENGTH/4];
	uint32_t byteCount;
	uint8_t bufferOffset;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

#ifdef __cplusplus
extern "C" 
{
#endif

void sha1_init(sha1nfo *s);


void sha1_writebyte(sha1nfo *s, uint8_t data);


void sha1_write(sha1nfo *s, const char *data, size_t len);


uint8_t* sha1_result(sha1nfo *s);


void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);


uint8_t* sha1_resultHmac(sha1nfo *s);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif
