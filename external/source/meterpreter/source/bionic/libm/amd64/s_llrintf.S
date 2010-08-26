#include <machine/asm.h>
__FBSDID("$FreeBSD: src/lib/msun/amd64/s_llrintf.S,v 1.1 2005/04/16 21:12:55 das Exp $")
	
/* sizeof(long) == sizeof(long long) */
#define	fn	llrintf
#include "s_lrintf.S"
