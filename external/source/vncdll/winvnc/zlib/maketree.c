/* maketree.c -- make inffixed.h table for decoding fixed codes
 * Copyright (C) 1995-2002 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h 
 */

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
 */

/* This program is included in the distribution for completeness.
   You do not need to compile or run this program since inffixed.h
   is already included in the distribution.  To use this program
   you need to compile zlib with BUILDFIXED defined and then compile
   and link this program with the zlib library.  Then the output of
   this program can be piped to inffixed.h. */

#include <stdio.h>
#include <stdlib.h>
#include "zutil.h"
#include "inftrees.h"

/* simplify the use of the inflate_huft type with some defines */
#define exop word.what.Exop
#define bits word.what.Bits

/* generate initialization table for an inflate_huft structure array */
void maketree(uInt b, inflate_huft *t)
{
  int i, e;

  i = 0;
  while (1)
  {
    e = t[i].exop;
    if (e && (e & (16+64)) == 0)        /* table pointer */
    {
      fprintf(stderr, "maketree: cannot initialize sub-tables!\n");
      exit(1);
    }
    if (i % 4 == 0)
      printf("\n   ");
    printf(" {{{%u,%u}},%u}", t[i].exop, t[i].bits, t[i].base);
    if (++i == (1<<b))
      break;
    putchar(',');
  }
  puts("");
}

/* create the fixed tables in C initialization syntax */
void main(void)
{
  int r;
  uInt bl, bd;
  inflate_huft *tl, *td;
  z_stream z;

  z.zalloc = zcalloc;
  z.opaque = (voidpf)0;
  z.zfree = zcfree;
  r = inflate_trees_fixed(&bl, &bd, &tl, &td, &z);
  if (r)
  {
    fprintf(stderr, "inflate_trees_fixed error %d\n", r);
    return;
  }
  puts("/* inffixed.h -- table for decoding fixed codes");
  puts(" * Generated automatically by the maketree.c program");
  puts(" */");
  puts("");
  puts("/* WARNING: this file should *not* be used by applications. It is");
  puts("   part of the implementation of the compression library and is");
  puts("   subject to change. Applications should only use zlib.h.");
  puts(" */");
  puts("");
  printf("local uInt fixed_bl = %d;\n", bl);
  printf("local uInt fixed_bd = %d;\n", bd);
  printf("local inflate_huft fixed_tl[] = {");
  maketree(bl, tl);
  puts("  };");
  printf("local inflate_huft fixed_td[] = {");
  maketree(bd, td);
  puts("  };");
}
