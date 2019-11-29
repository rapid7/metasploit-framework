//
//  lzssdec.h
//  img4tool
//
//  Code borrowed from: http://newosxbook.com/src.jl?tree=listings&file=joker.c
//  Coded by Jonathan Levin (a.k.a @Morpheus______), http://newosxbook.com

#ifndef lzssdec_h
#define lzssdec_h

#include <stdint.h>
#include <stdlib.h>

char *tryLZSS(char *compressed, size_t *filesize);

#endif /* lzssdec_h */
