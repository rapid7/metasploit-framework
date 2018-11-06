/*
20080913
D. J. Bernstein
Public domain.
*/

#include "sha512.h"

static void crypto_hashblocks_sha512(uint8_t *statebytes,const uint8_t *in,uint64_t inlen);

#define blocks crypto_hashblocks_sha512

static const uint8_t iv[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};

int crypto_hash_sha512(uint8_t *out,const uint8_t *in,uint64_t inlen)
{
  uint8_t h[64];
  uint8_t padded[256];
  uint64_t i;
  uint64_t bytes = inlen;

  for (i = 0;i < 64;++i) h[i] = iv[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks(h,padded,256);
  }

  for (i = 0;i < 64;++i) out[i] = h[i];

  return 0;
}

static uint64_t load_bigendian(const unsigned char *x)
{
  return
      (uint64_t) (x[7]) \
  | (((uint64_t) (x[6])) << 8) \
  | (((uint64_t) (x[5])) << 16) \
  | (((uint64_t) (x[4])) << 24) \
  | (((uint64_t) (x[3])) << 32) \
  | (((uint64_t) (x[2])) << 40) \
  | (((uint64_t) (x[1])) << 48) \
  | (((uint64_t) (x[0])) << 56)
  ;
}

static void store_bigendian(unsigned char *x,uint64_t u)
{
  x[7] = u; u >>= 8;
  x[6] = u; u >>= 8;
  x[5] = u; u >>= 8;
  x[4] = u; u >>= 8;
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define Sigma1(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define sigma0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x,7))
#define sigma1(x) (ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; \
  T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

static void crypto_hashblocks_sha512(uint8_t *statebytes,const uint8_t *in,uint64_t inlen)
{
  uint64_t state[8];
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
  uint64_t e;
  uint64_t f;
  uint64_t g;
  uint64_t h;
  uint64_t T1;
  uint64_t T2;

  a = load_bigendian(statebytes +  0); state[0] = a;
  b = load_bigendian(statebytes +  8); state[1] = b;
  c = load_bigendian(statebytes + 16); state[2] = c;
  d = load_bigendian(statebytes + 24); state[3] = d;
  e = load_bigendian(statebytes + 32); state[4] = e;
  f = load_bigendian(statebytes + 40); state[5] = f;
  g = load_bigendian(statebytes + 48); state[6] = g;
  h = load_bigendian(statebytes + 56); state[7] = h;

  while (inlen >= 128) {
    uint64_t w0  = load_bigendian(in +   0);
    uint64_t w1  = load_bigendian(in +   8);
    uint64_t w2  = load_bigendian(in +  16);
    uint64_t w3  = load_bigendian(in +  24);
    uint64_t w4  = load_bigendian(in +  32);
    uint64_t w5  = load_bigendian(in +  40);
    uint64_t w6  = load_bigendian(in +  48);
    uint64_t w7  = load_bigendian(in +  56);
    uint64_t w8  = load_bigendian(in +  64);
    uint64_t w9  = load_bigendian(in +  72);
    uint64_t w10 = load_bigendian(in +  80);
    uint64_t w11 = load_bigendian(in +  88);
    uint64_t w12 = load_bigendian(in +  96);
    uint64_t w13 = load_bigendian(in + 104);
    uint64_t w14 = load_bigendian(in + 112);
    uint64_t w15 = load_bigendian(in + 120);

    F(w0 ,0x428a2f98d728ae22ULL)
    F(w1 ,0x7137449123ef65cdULL)
    F(w2 ,0xb5c0fbcfec4d3b2fULL)
    F(w3 ,0xe9b5dba58189dbbcULL)
    F(w4 ,0x3956c25bf348b538ULL)
    F(w5 ,0x59f111f1b605d019ULL)
    F(w6 ,0x923f82a4af194f9bULL)
    F(w7 ,0xab1c5ed5da6d8118ULL)
    F(w8 ,0xd807aa98a3030242ULL)
    F(w9 ,0x12835b0145706fbeULL)
    F(w10,0x243185be4ee4b28cULL)
    F(w11,0x550c7dc3d5ffb4e2ULL)
    F(w12,0x72be5d74f27b896fULL)
    F(w13,0x80deb1fe3b1696b1ULL)
    F(w14,0x9bdc06a725c71235ULL)
    F(w15,0xc19bf174cf692694ULL)

    EXPAND

    F(w0 ,0xe49b69c19ef14ad2ULL)
    F(w1 ,0xefbe4786384f25e3ULL)
    F(w2 ,0x0fc19dc68b8cd5b5ULL)
    F(w3 ,0x240ca1cc77ac9c65ULL)
    F(w4 ,0x2de92c6f592b0275ULL)
    F(w5 ,0x4a7484aa6ea6e483ULL)
    F(w6 ,0x5cb0a9dcbd41fbd4ULL)
    F(w7 ,0x76f988da831153b5ULL)
    F(w8 ,0x983e5152ee66dfabULL)
    F(w9 ,0xa831c66d2db43210ULL)
    F(w10,0xb00327c898fb213fULL)
    F(w11,0xbf597fc7beef0ee4ULL)
    F(w12,0xc6e00bf33da88fc2ULL)
    F(w13,0xd5a79147930aa725ULL)
    F(w14,0x06ca6351e003826fULL)
    F(w15,0x142929670a0e6e70ULL)

    EXPAND

    F(w0 ,0x27b70a8546d22ffcULL)
    F(w1 ,0x2e1b21385c26c926ULL)
    F(w2 ,0x4d2c6dfc5ac42aedULL)
    F(w3 ,0x53380d139d95b3dfULL)
    F(w4 ,0x650a73548baf63deULL)
    F(w5 ,0x766a0abb3c77b2a8ULL)
    F(w6 ,0x81c2c92e47edaee6ULL)
    F(w7 ,0x92722c851482353bULL)
    F(w8 ,0xa2bfe8a14cf10364ULL)
    F(w9 ,0xa81a664bbc423001ULL)
    F(w10,0xc24b8b70d0f89791ULL)
    F(w11,0xc76c51a30654be30ULL)
    F(w12,0xd192e819d6ef5218ULL)
    F(w13,0xd69906245565a910ULL)
    F(w14,0xf40e35855771202aULL)
    F(w15,0x106aa07032bbd1b8ULL)

    EXPAND

    F(w0 ,0x19a4c116b8d2d0c8ULL)
    F(w1 ,0x1e376c085141ab53ULL)
    F(w2 ,0x2748774cdf8eeb99ULL)
    F(w3 ,0x34b0bcb5e19b48a8ULL)
    F(w4 ,0x391c0cb3c5c95a63ULL)
    F(w5 ,0x4ed8aa4ae3418acbULL)
    F(w6 ,0x5b9cca4f7763e373ULL)
    F(w7 ,0x682e6ff3d6b2b8a3ULL)
    F(w8 ,0x748f82ee5defb2fcULL)
    F(w9 ,0x78a5636f43172f60ULL)
    F(w10,0x84c87814a1f0ab72ULL)
    F(w11,0x8cc702081a6439ecULL)
    F(w12,0x90befffa23631e28ULL)
    F(w13,0xa4506cebde82bde9ULL)
    F(w14,0xbef9a3f7b2c67915ULL)
    F(w15,0xc67178f2e372532bULL)

    EXPAND

    F(w0 ,0xca273eceea26619cULL)
    F(w1 ,0xd186b8c721c0c207ULL)
    F(w2 ,0xeada7dd6cde0eb1eULL)
    F(w3 ,0xf57d4f7fee6ed178ULL)
    F(w4 ,0x06f067aa72176fbaULL)
    F(w5 ,0x0a637dc5a2c898a6ULL)
    F(w6 ,0x113f9804bef90daeULL)
    F(w7 ,0x1b710b35131c471bULL)
    F(w8 ,0x28db77f523047d84ULL)
    F(w9 ,0x32caab7b40c72493ULL)
    F(w10,0x3c9ebe0a15c9bebcULL)
    F(w11,0x431d67c49c100d4cULL)
    F(w12,0x4cc5d4becb3e42b6ULL)
    F(w13,0x597f299cfc657e2aULL)
    F(w14,0x5fcb6fab3ad6faecULL)
    F(w15,0x6c44198c4a475817ULL)

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 128;
    inlen -= 128;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  8,state[1]);
  store_bigendian(statebytes + 16,state[2]);
  store_bigendian(statebytes + 24,state[3]);
  store_bigendian(statebytes + 32,state[4]);
  store_bigendian(statebytes + 40,state[5]);
  store_bigendian(statebytes + 48,state[6]);
  store_bigendian(statebytes + 56,state[7]);
}
