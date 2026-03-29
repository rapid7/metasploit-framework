//
// License:
// https://github.com/rapid7/metasploit-framework/blob/master/LICENSE
//
// This code was originally obtained and modified from the following source
// by Bobin Verton:
// https://gist.github.com/rverton/a44fc8ca67ab9ec32089

#ifndef MSF_RC4_H
#define MSF_RC4_H

#include <string.h>

#define RC4_N 256

static void rc4_swap(unsigned char *a, unsigned char *b) {
  unsigned char tmp = *a;
  *a = *b;
  *b = tmp;
}

static void rc4_ksa(const char *key, unsigned char *S) {
  int len = (int)strlen(key);
  int j = 0;
  int i;
  for (i = 0; i < RC4_N; i++) S[i] = (unsigned char)i;
  for (i = 0; i < RC4_N; i++) {
    j = (j + S[i] + key[i % len]) % RC4_N;
    rc4_swap(&S[i], &S[j]);
  }
}

static void rc4_prga(unsigned char *S, const unsigned char *plaintext,
                     unsigned char *ciphertext, int len) {
  int i = 0, j = 0, n;
  for (n = 0; n < len; n++) {
    i = (i + 1) % RC4_N;
    j = (j + S[i]) % RC4_N;
    rc4_swap(&S[i], &S[j]);
    ciphertext[n] = S[(S[i] + S[j]) % RC4_N] ^ plaintext[n];
  }
}

static void RC4(const char *key, const unsigned char *plaintext,
                unsigned char *ciphertext, int len) {
  unsigned char S[RC4_N];
  rc4_ksa(key, S);
  rc4_prga(S, plaintext, ciphertext, len);
}

#endif /* MSF_RC4_H */
