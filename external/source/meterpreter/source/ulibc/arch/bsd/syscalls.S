#include "SYS.h"



RSYSCALL(close)
RSYSCALL(connect)
RSYSCALL(exit)
RSYSCALL(fstat)
RSYSCALL(gettimeofday)
RSYSCALL(getdtablesize)
RSYSCALL(getpid)		
RSYSCALL(getuid)		
RSYSCALL(ioctl)
RSYSCALL(lseek)
RSYSCALL(mmap)		
RSYSCALL(munmap)	
RSYSCALL(madvise)		
RSYSCALL(open)
RSYSCALL(poll)
RSYSCALL(read)
RSYSCALL(select)
RSYSCALL(socket)
/*	
*	RSYSCALL(sysctl)
*	this screws up PIE for some reason
*/
RSYSCALL(write)
	
