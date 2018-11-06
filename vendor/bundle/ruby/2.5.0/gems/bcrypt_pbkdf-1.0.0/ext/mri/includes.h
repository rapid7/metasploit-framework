#ifndef bcrypt_pbkdf_include_h
#define bcrypt_pbkdf_include_h

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <strings.h>

#if defined(_WIN32)

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;

#endif

#include "blf.h"

void explicit_bzero(void *p, size_t n);
int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
    uint8_t *key, size_t keylen, unsigned int rounds);
void bcrypt_hash(const uint8_t *sha2pass, const uint8_t *sha2salt, uint8_t *out);

#define BCRYPT_WORDS 8
#define BCRYPT_HASHSIZE (BCRYPT_WORDS * 4)

#endif