SRC_FILES := src/main.c src/env.c src/net.c src/nftnl.c src/file.c
OUT_NAME = ./exploit

# use musl-gcc since statically linking glibc with gcc generated invalid opcodes for qemu
#   and dynamically linking raised glibc ABI versioning errors
CC = musl-gcc

# use custom headers with fixed versions in a musl-gcc compatible manner
# - ./include/libmnl: libmnl v1.0.5
# - ./include/libnftnl: libnftnl v1.2.6
# - ./include/linux-lts-6.1.72: linux v6.1.72
CFLAGS = -I./include -I./include/linux-lts-6.1.72 -Wall -Wno-deprecated-declarations

# use custom object archives compiled with musl-gcc for compatibility. normal ones 
#   are used with gcc and have _chk funcs which musl doesn't support
# the versions are the same as the headers above
LIBMNL_PATH = ./lib/libmnl.a
LIBNFTNL_PATH = ./lib/libnftnl.a

exploit: _compile_static _strip_bin
run: _run_outfile
clean: _clean_outfile

_compile_static:
	$(CC) $(CFLAGS) $(SRC_FILES) -o $(OUT_NAME) -static $(LIBNFTNL_PATH) $(LIBMNL_PATH)
_strip_bin:
	strip $(OUT_NAME)
_run_outfile:
	$(OUT_NAME)
_clean_outfile:
	rm $(OUT_NAME)