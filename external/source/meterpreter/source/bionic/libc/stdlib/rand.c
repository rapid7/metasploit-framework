#include <stdlib.h>

// http://burtleburtle.net/bob/rand/smallprng.html
// random modifications just for fun ;p

#define rot(x,k) (((x)<<(k))|((x)>>(32-(k))))

struct __prng_ctx { 
	unsigned long int a, b, c, d;
};

struct __prng_ctx __prng_state; // XXX< mark as private visibility

int rand(void)
{
	int ret;
	unsigned long int e = __prng_state.a - rot(__prng_state.b, 23);
	__prng_state.a = __prng_state.b ^ rot(__prng_state.c, 16);
	__prng_state.b = __prng_state.c + rot(__prng_state.d, 11);
	__prng_state.c = __prng_state.d + e;
	__prng_state.d = e + __prng_state.a;

	ret = __prng_state.d;
	if(ret < 0) ret = -ret; 
	return ret;
}


void srand(unsigned int seed)
{
	int i;
	__prng_state.a = 0xdea110c8 * seed; 
	__prng_state.b = seed ^ 0xcafebabe;
	__prng_state.c = seed - 0x41414141; 
	__prng_state.d = ~seed;

	for(i = 0; i < 128; i++) rand();
}

long random(void)
{
	return rand() ^ 0x5a5aa5a5;
}

void srandom(unsigned int seed)
{
	return srand(~seed);
}
