#include "linux-in-mem-exe.h"

/*
 * Implementing this is a little tricky. 
 *
 * Need:
 *   - raw sys calls with hidden symbols (prevent symbol conflicts) (if we use libc etc and
 *     we unmap it, it will crash.
 *   - clear up memory (munmap(0, 0x80000000) .. might be possible to do portably across kernel revisions)
 *   - probably ideal to use signal handlers and scan memory
 *   - can probably align this function on a page boundary, and unmap everything not in this section.
 *   - standard userland exec stuff
 *   
 *  xxx. fork(), child ptrace's parent, ? ptrace is a bad idea. might be disabled.
 *  
 */

void perform_in_mem_exe(char **argv, char **environ, void *buffer)
{
	
}
