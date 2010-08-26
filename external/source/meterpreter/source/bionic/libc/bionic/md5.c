/*
 * Copyright (c) 1995 - 2001 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"

__RCSID("$Heimdal: md5.c,v 1.15 2001/01/29 04:33:44 assar Exp $"
        "$NetBSD: md5.c,v 1.1.1.4 2002/09/12 12:41:42 joda Exp $");
#endif

#include "md5.h"
#include "hash.h"

#define A m->counter[0]
#define B m->counter[1]
#define C m->counter[2]
#define D m->counter[3]
#define X data

void
MD5_Init (struct md5 *m)
{
  m->sz[0] = 0;
  m->sz[1] = 0;
  D = 0x10325476;
  C = 0x98badcfe;
  B = 0xefcdab89;
  A = 0x67452301;
}

#define F(x,y,z) CRAYFIX((x & y) | (~x & z))
#define G(x,y,z) CRAYFIX((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) CRAYFIX(y ^ (x | ~z))

#define DOIT(a,b,c,d,k,s,i,OP) \
a = b + cshift(a + OP(b,c,d) + X[k] + (i), s)

#define DO1(a,b,c,d,k,s,i) DOIT(a,b,c,d,k,s,i,F)
#define DO2(a,b,c,d,k,s,i) DOIT(a,b,c,d,k,s,i,G)
#define DO3(a,b,c,d,k,s,i) DOIT(a,b,c,d,k,s,i,H)
#define DO4(a,b,c,d,k,s,i) DOIT(a,b,c,d,k,s,i,I)

static inline void
calc (struct md5 *m, u_int32_t *data)
{
  u_int32_t AA, BB, CC, DD;

  AA = A;
  BB = B;
  CC = C;
  DD = D;

  /* Round 1 */

  DO1(A,B,C,D,0,7,0xd76aa478);
  DO1(D,A,B,C,1,12,0xe8c7b756);
  DO1(C,D,A,B,2,17,0x242070db);
  DO1(B,C,D,A,3,22,0xc1bdceee);

  DO1(A,B,C,D,4,7,0xf57c0faf);
  DO1(D,A,B,C,5,12,0x4787c62a);
  DO1(C,D,A,B,6,17,0xa8304613);
  DO1(B,C,D,A,7,22,0xfd469501);

  DO1(A,B,C,D,8,7,0x698098d8);
  DO1(D,A,B,C,9,12,0x8b44f7af);
  DO1(C,D,A,B,10,17,0xffff5bb1);
  DO1(B,C,D,A,11,22,0x895cd7be);

  DO1(A,B,C,D,12,7,0x6b901122);
  DO1(D,A,B,C,13,12,0xfd987193);
  DO1(C,D,A,B,14,17,0xa679438e);
  DO1(B,C,D,A,15,22,0x49b40821);

  /* Round 2 */

  DO2(A,B,C,D,1,5,0xf61e2562);
  DO2(D,A,B,C,6,9,0xc040b340);
  DO2(C,D,A,B,11,14,0x265e5a51);
  DO2(B,C,D,A,0,20,0xe9b6c7aa);

  DO2(A,B,C,D,5,5,0xd62f105d);
  DO2(D,A,B,C,10,9,0x2441453);
  DO2(C,D,A,B,15,14,0xd8a1e681);
  DO2(B,C,D,A,4,20,0xe7d3fbc8);

  DO2(A,B,C,D,9,5,0x21e1cde6);
  DO2(D,A,B,C,14,9,0xc33707d6);
  DO2(C,D,A,B,3,14,0xf4d50d87);
  DO2(B,C,D,A,8,20,0x455a14ed);

  DO2(A,B,C,D,13,5,0xa9e3e905);
  DO2(D,A,B,C,2,9,0xfcefa3f8);
  DO2(C,D,A,B,7,14,0x676f02d9);
  DO2(B,C,D,A,12,20,0x8d2a4c8a);

  /* Round 3 */

  DO3(A,B,C,D,5,4,0xfffa3942);
  DO3(D,A,B,C,8,11,0x8771f681);
  DO3(C,D,A,B,11,16,0x6d9d6122);
  DO3(B,C,D,A,14,23,0xfde5380c);

  DO3(A,B,C,D,1,4,0xa4beea44);
  DO3(D,A,B,C,4,11,0x4bdecfa9);
  DO3(C,D,A,B,7,16,0xf6bb4b60);
  DO3(B,C,D,A,10,23,0xbebfbc70);

  DO3(A,B,C,D,13,4,0x289b7ec6);
  DO3(D,A,B,C,0,11,0xeaa127fa);
  DO3(C,D,A,B,3,16,0xd4ef3085);
  DO3(B,C,D,A,6,23,0x4881d05);

  DO3(A,B,C,D,9,4,0xd9d4d039);
  DO3(D,A,B,C,12,11,0xe6db99e5);
  DO3(C,D,A,B,15,16,0x1fa27cf8);
  DO3(B,C,D,A,2,23,0xc4ac5665);

  /* Round 4 */

  DO4(A,B,C,D,0,6,0xf4292244);
  DO4(D,A,B,C,7,10,0x432aff97);
  DO4(C,D,A,B,14,15,0xab9423a7);
  DO4(B,C,D,A,5,21,0xfc93a039);

  DO4(A,B,C,D,12,6,0x655b59c3);
  DO4(D,A,B,C,3,10,0x8f0ccc92);
  DO4(C,D,A,B,10,15,0xffeff47d);
  DO4(B,C,D,A,1,21,0x85845dd1);

  DO4(A,B,C,D,8,6,0x6fa87e4f);
  DO4(D,A,B,C,15,10,0xfe2ce6e0);
  DO4(C,D,A,B,6,15,0xa3014314);
  DO4(B,C,D,A,13,21,0x4e0811a1);

  DO4(A,B,C,D,4,6,0xf7537e82);
  DO4(D,A,B,C,11,10,0xbd3af235);
  DO4(C,D,A,B,2,15,0x2ad7d2bb);
  DO4(B,C,D,A,9,21,0xeb86d391);

  A += AA;
  B += BB;
  C += CC;
  D += DD;
}

/*
 * From `Performance analysis of MD5' by Joseph D. Touch <touch@isi.edu>
 */

#if defined(WORDS_BIGENDIAN)
static inline u_int32_t
swap_u_int32_t (u_int32_t t)
{
  u_int32_t temp1, temp2;

  temp1   = cshift(t, 16);
  temp2   = temp1 >> 8;
  temp1  &= 0x00ff00ff;
  temp2  &= 0x00ff00ff;
  temp1 <<= 8;
  return temp1 | temp2;
}
#endif

struct x32{
  unsigned int a:32;
  unsigned int b:32;
};

void
MD5_Update (struct md5 *m, const void *v, size_t len)
{
  const unsigned char *p = v;
  size_t old_sz = m->sz[0];
  size_t offset;

  m->sz[0] += len * 8;
  if (m->sz[0] < old_sz)
      ++m->sz[1];
  offset = (old_sz / 8)  % 64;
  while(len > 0){
    size_t l = min(len, 64 - offset);
    memcpy(m->save + offset, p, l);
    offset += l;
    p += l;
    len -= l;
    if(offset == 64){
#if defined(WORDS_BIGENDIAN)
      int i;
      u_int32_t current[16];
      struct x32 *u = (struct x32*)m->save;
      for(i = 0; i < 8; i++){
	current[2*i+0] = swap_u_int32_t(u[i].a);
	current[2*i+1] = swap_u_int32_t(u[i].b);
      }
      calc(m, current);
#else
      calc(m, (u_int32_t*)m->save);
#endif
      offset = 0;
    }
  }
}

void
MD5_Final (void *res, struct md5 *m)
{
  static unsigned char zeros[72];
  unsigned offset = (m->sz[0] / 8) % 64;
  unsigned int dstart = (120 - offset - 1) % 64 + 1;

  *zeros = 0x80;
  memset (zeros + 1, 0, sizeof(zeros) - 1);
  zeros[dstart+0] = (m->sz[0] >> 0) & 0xff;
  zeros[dstart+1] = (m->sz[0] >> 8) & 0xff;
  zeros[dstart+2] = (m->sz[0] >> 16) & 0xff;
  zeros[dstart+3] = (m->sz[0] >> 24) & 0xff;
  zeros[dstart+4] = (m->sz[1] >> 0) & 0xff;
  zeros[dstart+5] = (m->sz[1] >> 8) & 0xff;
  zeros[dstart+6] = (m->sz[1] >> 16) & 0xff;
  zeros[dstart+7] = (m->sz[1] >> 24) & 0xff;
  MD5_Update (m, zeros, dstart + 8);
  {
      int i;
      unsigned char *r = (unsigned char *)res;

      for (i = 0; i < 4; ++i) {
	  r[4*i]   = m->counter[i] & 0xFF;
	  r[4*i+1] = (m->counter[i] >> 8) & 0xFF;
	  r[4*i+2] = (m->counter[i] >> 16) & 0xFF;
	  r[4*i+3] = (m->counter[i] >> 24) & 0xFF;
      }
  }
#if 0
  {
    int i;
    u_int32_t *r = (u_int32_t *)res;

    for (i = 0; i < 4; ++i)
      r[i] = swap_u_int32_t (m->counter[i]);
  }
#endif
}
