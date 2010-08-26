#include <machine/asm.h>
__FBSDID("$FreeBSD: src/lib/msun/amd64/s_llrint.S,v 1.1 2005/01/15 03:32:28 das Exp $")
	
/* sizeof(long) == sizeof(long long) */
#define	fn	llrint
#include "s_lrint.S"
