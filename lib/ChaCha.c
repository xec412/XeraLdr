#include <Windows.h>
#include "ChaCha.h"
#include "Common.h"

#define ROL(x,n) _rotl(x,n)

#define QUARTERROUND(a,b,c,d) \
  x[a] += x[b]; x[d] = ROL(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROL(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROL(x[d] ^ x[a],  8); \
  x[c] += x[d]; x[b] = ROL(x[b] ^ x[c],  7);

void s_chacha_block(unsigned char* output, const ULONG32* input, int rounds)
{
    ULONG32 x[16];
    int i;
    MEMCPY(x, input, sizeof(x));
    for (i = rounds; i > 0; i -= 2) {
        QUARTERROUND(0, 4, 8, 12)
            QUARTERROUND(1, 5, 9, 13)
            QUARTERROUND(2, 6, 10, 14)
            QUARTERROUND(3, 7, 11, 15)
            QUARTERROUND(0, 5, 10, 15)
            QUARTERROUND(1, 6, 11, 12)
            QUARTERROUND(2, 7, 8, 13)
            QUARTERROUND(3, 4, 9, 14)
    }
    for (i = 0; i < 16; ++i) {
        x[i] += input[i];
        STORE32L(x[i], output + 4 * i);
    }
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with ChaCha
   @param st      The ChaCha state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int chacha_crypt(chacha_state* st, const unsigned char* in, unsigned long inlen, unsigned char* out)
{
    unsigned char buf[64];
    unsigned long i, j;

    if (inlen == 0) return CRYPT_OK; /* nothing to do */

    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(in != NULL);
    LTC_ARGCHK(out != NULL);
    LTC_ARGCHK(st->ivlen != 0);

    if (st->ksleft > 0) {
        j = MIN(st->ksleft, inlen);
        for (i = 0; i < j; ++i, st->ksleft--) out[i] = in[i] ^ st->kstream[64 - st->ksleft];
        inlen -= j;
        if (inlen == 0) return CRYPT_OK;
        out += j;
        in += j;
    }
    for (;;) {
        s_chacha_block(buf, st->input, st->rounds);
        if (st->ivlen == 8) {
            /* IV-64bit, increment 64bit counter */
            if (0 == ++st->input[12] && 0 == ++st->input[13]) return CRYPT_OVERFLOW;
        }
        else {
            /* IV-96bit, increment 32bit counter */
            if (0 == ++st->input[12]) return CRYPT_OVERFLOW;
        }
        if (inlen <= 64) {
            for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
            st->ksleft = 64 - inlen;
            for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
            return CRYPT_OK;
        }
        for (i = 0; i < 64; ++i) out[i] = in[i] ^ buf[i];
        inlen -= 64;
        out += 64;
        in += 64;
    }
}


/**
  Set IV + counter data to the ChaCha state
  @param st      The ChaCha20 state
  @param iv      The IV data to add
  @param ivlen   The length of the IV (must be 12)
  @param counter 32bit (unsigned) initial counter value
  @return CRYPT_OK on success
 */
int chacha_ivctr32(chacha_state* st, const unsigned char* iv, unsigned long ivlen, ULONG32 counter)
{
    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(iv != NULL);
    /* 96bit IV + 32bit counter */
    LTC_ARGCHK(ivlen == 12);

    st->input[12] = counter;
    LOAD32L(st->input[13], iv + 0);
    LOAD32L(st->input[14], iv + 4);
    LOAD32L(st->input[15], iv + 8);
    st->ksleft = 0;
    st->ivlen = ivlen;
    return CRYPT_OK;
}

/**
  Set IV + counter data to the ChaCha state
  @param st      The ChaCha20 state
  @param iv      The IV data to add
  @param ivlen   The length of the IV (must be 8)
  @param counter 64bit (unsigned) initial counter value
  @return CRYPT_OK on success
 */
int chacha_ivctr64(chacha_state* st, const unsigned char* iv, unsigned long ivlen, ULONG64 counter)
{
    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(iv != NULL);
    /* 64bit IV + 64bit counter */
    LTC_ARGCHK(ivlen == 8);

    st->input[12] = (ULONG32)(counter & 0xFFFFFFFF);
    st->input[13] = (ULONG32)(counter >> 32);
    LOAD32L(st->input[14], iv + 0);
    LOAD32L(st->input[15], iv + 4);
    st->ksleft = 0;
    st->ivlen = ivlen;
    return CRYPT_OK;
}

/**
  Generate a stream of random bytes via ChaCha
  @param st      The ChaCha20 state
  @param out     [out] The output buffer
  @param outlen  The output length
  @return CRYPT_OK on success
 */
int chacha_keystream(chacha_state* st, unsigned char* out, unsigned long outlen)
{
    if (outlen == 0) return CRYPT_OK; /* nothing to do */
    LTC_ARGCHK(out != NULL);
    MEMSET(out, 0, outlen);
    return chacha_crypt(st, out, outlen, out);
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with ChaCha
   @param key     The key
   @param keylen  The key length
   @param iv      The initial vector
   @param ivlen   The initial vector length
   @param datain  The plaintext (or ciphertext)
   @param datalen The length of the input and output (octets)
   @param rounds  The number of rounds
   @param dataout [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int chacha_memory(const unsigned char *key,    unsigned long keylen,  unsigned long rounds,
                  const unsigned char *iv,     unsigned long ivlen,   ULONG64 counter,
                  const unsigned char *datain, unsigned long datalen, unsigned char *dataout)
{
    chacha_state st;
    int err;

    LTC_ARGCHK(ivlen <= 8 || counter < 4294967296);

    if ((err = chacha_setup(&st, key, keylen, rounds))       != CRYPT_OK) goto WIPE_KEY;
    if (ivlen > 8) {
        if ((err = chacha_ivctr32(&st, iv, ivlen, (ULONG32)counter)) != CRYPT_OK) goto WIPE_KEY;
    } else {
        if ((err = chacha_ivctr64(&st, iv, ivlen, counter)) != CRYPT_OK) goto WIPE_KEY;
    }
    err = chacha_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
    chacha_done(&st);
    return err;
}

/**
   Initialize an ChaCha context (only the key)
   @param st        [out] The destination of the ChaCha state
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @param rounds    Number of rounds (e.g. 20 for ChaCha20)
   @return CRYPT_OK if successful
*/
int chacha_setup(chacha_state* st, const unsigned char* key, unsigned long keylen, int rounds)
{
    const char* sigma = "expand 32-byte k";
    const char* tau = "expand 16-byte k";

    const char* constants;

    LTC_ARGCHK(st != NULL);
    LTC_ARGCHK(key != NULL);
    LTC_ARGCHK(keylen == 32 || keylen == 16);

    if (rounds == 0) rounds = 20;

    LOAD32L(st->input[4], key + 0);
    LOAD32L(st->input[5], key + 4);
    LOAD32L(st->input[6], key + 8);
    LOAD32L(st->input[7], key + 12);

    if (keylen == 32) { /* 256bit */
        key += 16;
        constants = sigma;
    }
    else { /* 128bit */
        constants = tau;
    }

    LOAD32L(st->input[8], key + 0);
    LOAD32L(st->input[9], key + 4);
    LOAD32L(st->input[10], key + 8);
    LOAD32L(st->input[11], key + 12);
    LOAD32L(st->input[0], constants + 0);
    LOAD32L(st->input[1], constants + 4);
    LOAD32L(st->input[2], constants + 8);
    LOAD32L(st->input[3], constants + 12);
    st->rounds = rounds; /* e.g. 20 for chacha20 */
    st->ivlen = 0; /* will be set later by chacha_ivctr(32|64) */
    return CRYPT_OK;
}

/**
  Terminate and clear ChaCha state
  @param st      The ChaCha state
  @return CRYPT_OK on success
*/
int chacha_done(chacha_state* st)
{
    LTC_ARGCHK(st != NULL);
    MEMSET(st, 0, sizeof(chacha_state));
    return CRYPT_OK;
}