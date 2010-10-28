#include "linux-in-mem-exe.h"

/*
 * We will implement the userland exec via the remote host sending us a
 * buffer formatted like the following:
 *
 * [ executable text / data ] 
 * 
 * We will build a memory mapping of the following:
 *
 * [ text / data | guard page | stub code | guard | stack ]
 *
 * To transfer execution, we will set up the stack as a standard binary would
 * expect it (argc / argv, etc.). Once the memory has been prepared, we will
 * then hand off execution to the stub code. The stub code will be 
 * responsible for: 
 *  - unmapping the memory before and after the allocated memory
 *  - setting up a segv handler to reset eip.
 *  - mremap()'ing the allocated memory to the base address.
 *  - resetting the signal handlers to default
 *  - transferring code to the entry point.
 */

static void patch_blob(unsigned char *blob, unsigned long int find, unsigned long int patch)
{
	unsigned long int *ptr;

	ptr = memmem(blob, 4096, &find, sizeof(unsigned long int));
	if(ptr == NULL) {
		dprintf("patch job failed .. stub code probably won't work / will crash");
		return;
	}

	dprintf("found %p, will patch memory [%p] with patch value of %p", find, ptr, patch);
	*ptr = patch;
}

void perform_in_mem_exe(char **argv, char **environ, void *buffer, size_t length, unsigned long int base, unsigned long int entry)
{
	unsigned char *m, *esp, *saved_envp, *saved_argv, *b;
	size_t tl;
	int i, env_count, arg_count, j;
	unsigned long int *ptr, val;

	Elf32_auxv_t *auxv;

	if(length & 4095) {
		dprintf("remote host forgot to elf2bin payload");
		return;
	}

	dprintf("argv: %p, environ: %p, buffer: %p, length: %p, base: %p, entry: %p", 
		argv, environ, buffer, length, base, entry);

	tl = length + (4096 * 4) + (1024 * 1024 * 2);
	
	b = (unsigned char *)(buffer);
	do {
		// loop until we get a clean range of memory. 
		m = mmap(NULL, tl, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		dprintf("allocated memory at %p", m);
	} while(m >= b && m <= (b + tl) || (m+tl) >= b && (m+tl) <= (b+tl));

	// prepare the executable range
	dprintf("copying executable image over");
	memcpy(m, buffer, length);

	// set up the guard pages
	dprintf("setting up guard pages");
	mprotect(m+length, 4096, PROT_NONE);
	mprotect(m+length+(4096 * 3), 4096, PROT_NONE);

	// prepare the stub code
	dprintf("copying stub code");
	memcpy(m+length+4096, linux_stub, linux_stub_len);
	
	dprintf("patching stub code with dynamic values");
	//   length - munmap up to start of m
	patch_blob(m+length+4096, 0x42424242, (unsigned long int)(m));
	patch_blob(m+length+4096, 0x43434343, (unsigned long int)(m)+tl);
	patch_blob(m+length+4096, 0x44444444, 0x80000000 - ((unsigned long int)(m)+tl));

	patch_blob(m+length+4096, 0x45454545, (unsigned long int)(m));
	patch_blob(m+length+4096, 0x46464646, base);
	patch_blob(m+length+4096, 0x47474747, (length/4096)+1); // +1 includes guard page.

	patch_blob(m+length+4096, 0x48484848, (unsigned long int)(m+length+(4096 * 3)));
	patch_blob(m+length+4096, 0x49494949, base + length + (4096 * 3));
	patch_blob(m+length+4096, 0x4a4a4a4a, ((1024*1024*2)/4096)+1);

	patch_blob(m+length+4096, 0x4b4b4b4b, entry);	

#define DEBUG_STUB
#ifndef DEBUG_STUB
	do {
		unsigned char *loc;
		loc = memchr(m+length+4096, 4096, 0xcc);
		if(loc) {
			*loc = 0x90;
		}
	} while(0);
#endif

	// prepare stack :~(
	esp = (m + tl) - 4;
	//   copy environ

	for(env_count = 0; environ[env_count]; env_count++);
	dprintf("env_count is %d, copying strings", env_count);

	for(i = env_count-1; i >= 0; i--) {
		dprintf("--> environ[%d] = [%s]", i, environ[i]); 
		esp -= strlen(environ[i]) + 1;
		strcpy(esp, environ[i]);
	}
	saved_envp = esp;

	for(arg_count = 0; argv[arg_count]; arg_count++);
	dprintf("arg_count is %d, copying strings", arg_count);

	for(i = arg_count-1; i >= 0; i--) {
		dprintf("--> argv[%d] = [%s]", i, argv[i]);
		esp -= strlen(argv[i]) + 1;
		strcpy(esp, argv[i]);
	}
	saved_argv = esp;

	//   round down and insert a NULL
	esp -= 4 + ((unsigned long int)(esp) % 4);
	
	dprintf("setting up auxv headers");
	//   set up the auxillary headers
	esp -= sizeof(Elf32_auxv_t) * 7;
	auxv = (Elf32_auxv_t *)(esp);
	auxv[6].a_type = AT_NULL; 
	auxv[5].a_type = AT_PAGESZ; auxv[5].a_un.a_val = 4096; // XXX, replace when porting to another arch.
	auxv[4].a_type = AT_PHDR; auxv[4].a_un.a_val = 0; // if it crashes with a npd, we'll know why.
	auxv[3].a_type = AT_PHNUM; auxv[3].a_un.a_val = 0; // XXX, fix me.
	auxv[2].a_type = AT_BASE; auxv[2].a_un.a_val = (unsigned long int)(base);
	auxv[1].a_type = AT_FLAGS; // flags set to 0 due to mmap
	auxv[0].a_type = AT_ENTRY; auxv[0].a_un.a_val = entry;

	//   prepare envp
	
	esp -= (sizeof(unsigned long int) * (env_count+1));
	ptr = (unsigned long int *)(esp);

	//   this is fucky because we have to put in the addresses as it will be 
	//   when the remote process starts.

	dprintf("preparing envp pointers");

	for(i = 0; i < env_count; i++) {
		*ptr++ = ((unsigned long int)(saved_envp) - (unsigned long int)(m)) + base;
		j = strlen(saved_envp) + 1;
		saved_envp += j;
	}
	*ptr++ = NULL;

	saved_envp = ((unsigned long int)(esp) - (unsigned long int)(m)) + base; 

	esp -= (sizeof(unsigned long int) * (arg_count+1));
	ptr = (unsigned long int *)(esp);
	
	// same again, translate the addresses we write to what it will
	// be when it is in it's correct place.

	dprintf("preparing argv pointers");

	for(i = 0; i < arg_count; i++) {
		*ptr++ = ((unsigned long int)(saved_argv) - (unsigned long int)(m)) + base;
		j = strlen(saved_argv) + 1;
		saved_argv += j;
	}
	*ptr++ = NULL;
	saved_argv = ((unsigned long int)(esp) - (unsigned long int)(m)) + base;

	esp -= sizeof(unsigned long int);
	ptr = (unsigned int *)(esp);
	*ptr = arg_count;

	dprintf("setting signal handler");

	// reset all signal handlers

	for(i = 0; i < 128; i++) {
		signal(i, SIG_DFL);
	}

	// point esp to the what it will be at the end :-)
	val = base + ((unsigned long int)(esp) - (unsigned long int)(m));
	dprintf("base is at %p, our new esp is at %p, diff = %p", base, val, val - base);

	ptr = (unsigned long int *)(m+length+(4096 * 3)-4);
	*ptr = val;

	// point of no return. hand off execution to the stub code. 
	__asm__("movl %0, %%esp; jmp *%1" :: "r" (ptr), "r" (m + length + 4096));

}

unsigned char linux_stub[] = {
  0xb8, 0x5b, 0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x42,
  0x42, 0x42, 0x42, 0xcd, 0x80, 0xb8, 0x5b, 0x00, 0x00, 0x00, 0xbb, 0x43,
  0x43, 0x43, 0x43, 0xb9, 0x44, 0x44, 0x44, 0x44, 0xcd, 0x80, 0xb8, 0x5b,
  0x00, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x80, 0xb9, 0x00, 0x00, 0x00,
  0x40, 0xcd, 0x80, 0xbb, 0x45, 0x45, 0x45, 0x45, 0xbf, 0x46, 0x46, 0x46,
  0x46, 0xbd, 0x47, 0x47, 0x47, 0x47, 0xe8, 0x1d, 0x00, 0x00, 0x00, 0xbb,
  0x48, 0x48, 0x48, 0x48, 0xbf, 0x49, 0x49, 0x49, 0x49, 0xbd, 0x4a, 0x4a,
  0x4a, 0x4a, 0xe8, 0x09, 0x00, 0x00, 0x00, 0x5c, 0xcc, 0xb8, 0x4b, 0x4b,
  0x4b, 0x4b, 0xff, 0xe0, 0xb9, 0x00, 0x10, 0x00, 0x00, 0xba, 0x00, 0x10,
  0x00, 0x00, 0xbe, 0x03, 0x00, 0x00, 0x00, 0xb8, 0xa3, 0x00, 0x00, 0x00,
  0xcd, 0x80, 0x81, 0xc3, 0x00, 0x10, 0x00, 0x00, 0x81, 0xc7, 0x00, 0x10,
  0x00, 0x00, 0x4d, 0x75, 0xea, 0xc3
};
unsigned int linux_stub_len = 138;
