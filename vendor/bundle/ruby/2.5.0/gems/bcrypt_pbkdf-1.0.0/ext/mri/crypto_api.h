#define crypto_hash_sha512_BYTES 64U
int crypto_hashblocks_sha512(unsigned char *statebytes,const unsigned char *in,unsigned long long inlen);
int crypto_hash_sha512(unsigned char *out,const unsigned char *in,unsigned long long inlen);