#pragma once

#include <Windows.h>

#define STORE32L(x, y)                                                                     \
  do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y)                            \
  do { x = ((ULONG32)((y)[3] & 255)<<24) | \
           ((ULONG32)((y)[2] & 255)<<16) | \
           ((ULONG32)((y)[1] & 255)<<8)  | \
           ((ULONG32)((y)[0] & 255)); } while(0)

#define STORE64L(x, y)                                                                     \
  do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                       \
  do { x = (((ULONG64)((y)[7] & 255))<<56)|(((ULONG64)((y)[6] & 255))<<48)| \
           (((ULONG64)((y)[5] & 255))<<40)|(((ULONG64)((y)[4] & 255))<<32)| \
           (((ULONG64)((y)[3] & 255))<<24)|(((ULONG64)((y)[2] & 255))<<16)| \
           (((ULONG64)((y)[1] & 255))<<8)|(((ULONG64)((y)[0] & 255))); } while(0)

#define STORE32H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y)                            \
  do { x = ((ULONG32)((y)[0] & 255)<<24) | \
           ((ULONG32)((y)[1] & 255)<<16) | \
           ((ULONG32)((y)[2] & 255)<<8)  | \
           ((ULONG32)((y)[3] & 255)); } while(0)

#define STORE64H(x, y)                                                                     \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)                                                      \
do { x = (((ULONG64)((y)[0] & 255))<<56)|(((ULONG64)((y)[1] & 255))<<48) | \
         (((ULONG64)((y)[2] & 255))<<40)|(((ULONG64)((y)[3] & 255))<<32) | \
         (((ULONG64)((y)[4] & 255))<<24)|(((ULONG64)((y)[5] & 255))<<16) | \
         (((ULONG64)((y)[6] & 255))<<8)|(((ULONG64)((y)[7] & 255))); } while(0)


#ifndef MAX
#define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#define LTC_ARGCHK( x ) if ( ! ( x ) ) return CRYPT_ERROR;
#define CHACHA_KEYLEN   32
#define CHACHA_IVLEN    12

/* error codes [will be expanded in future releases] */
enum {
    CRYPT_OK = 0,             /* Result OK */
    CRYPT_ERROR,            /* Generic Error */
    CRYPT_NOP,              /* Not a failure but no operation was performed */

    CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
    CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
    CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

    CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
    CRYPT_INVALID_PACKET,   /* Invalid input packet given */

    CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
    CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

    CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
    CRYPT_INVALID_HASH,     /* Invalid hash specified */
    CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

    CRYPT_MEM,              /* Out of memory */

    CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
    CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

    CRYPT_INVALID_ARG,      /* Generic invalid argument */
    CRYPT_FILE_NOTFOUND,    /* File Not Found */

    CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */

    CRYPT_OVERFLOW,         /* An overflow of a value was detected/prevented */

    CRYPT_PK_ASN1_ERROR,    /* An error occurred while en- or decoding ASN.1 data */

    CRYPT_INPUT_TOO_LONG,   /* The input was longer than expected. */

    CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

    CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
    CRYPT_PK_INVALID_PADDING, /* Invalid padding on input */

    CRYPT_HASH_OVERFLOW      /* Hash applied to too many bits */
};


typedef struct {
    ULONG32 input[16];
    unsigned char kstream[64];
    unsigned long ksleft;
    unsigned long ivlen;
    int rounds;
} chacha_state;

int chacha_setup(chacha_state* st, const unsigned char* key, unsigned long keylen, int rounds);
int chacha_ivctr32(chacha_state* st, const unsigned char* iv, unsigned long ivlen, ULONG32 counter);
int chacha_ivctr64(chacha_state* st, const unsigned char* iv, unsigned long ivlen, ULONG64 counter);
int chacha_crypt(chacha_state* st, const unsigned char* in, unsigned long inlen, unsigned char* out);
int chacha_keystream(chacha_state* st, unsigned char* out, unsigned long outlen);
int chacha_done(chacha_state* st);
int chacha_memory(const unsigned char* key, unsigned long keylen, unsigned long rounds,
    const unsigned char* iv, unsigned long ivlen, ULONG64 counter,
    const unsigned char* datain, unsigned long datalen, unsigned char* dataout);
