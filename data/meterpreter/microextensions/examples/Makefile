PAYLOADS ?= ../../../../../metasploit-payloads
COMMON := $(PAYLOADS)/c/meterpreter/source/common
X64_CC := x86_64-w64-mingw32-gcc
X64_NM := x86_64-w64-mingw32-nm
X64_OBJDUMP := x86_64-w64-mingw32-objdump
X86_CC := i686-w64-mingw32-gcc
X86_NM := i686-w64-mingw32-nm
X86_OBJDUMP := i686-w64-mingw32-objdump

CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-builtin \
	-fno-ident -fno-stack-protector -fno-asynchronous-unwind-tables \
	-Wno-cast-function-type -Wno-missing-field-initializers -Wno-unused-function \
	-D_WIN32_WINNT=0x0601 -DWINVER=0x0601 \
	-Iinclude -Istdapi/include -I$(COMMON)

X64_OBJECTS := build/sysinfo.x64.o build/listing.x64.o build/fs_file.x64.o build/fs_operations.x64.o build/fs_hash.x64.o build/fs_mount.x64.o build/fs_search.x64.o build/railgun_api.x64.o build/echo.x64.o
X86_OBJECTS := build/sysinfo.x86.o build/listing.x86.o build/fs_file.x86.o build/fs_operations.x86.o build/fs_hash.x86.o build/fs_mount.x86.o build/fs_search.x86.o build/railgun_api.x86.o build/echo.x86.o
OBJECTS := $(X64_OBJECTS) $(X86_OBJECTS)

.PHONY: all clean verify

all: $(OBJECTS)

build/sysinfo.x64.o: stdapi/src/system/sysinfo.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/listing.x64.o: stdapi/src/listing/listing.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/fs_file.x64.o: stdapi/src/fs/file.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/fs_operations.x64.o: stdapi/src/fs/operations.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/fs_hash.x64.o: stdapi/src/fs/hash.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/fs_mount.x64.o: stdapi/src/fs/mount.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/fs_search.x64.o: stdapi/src/fs/search.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/railgun_api.x64.o: stdapi/src/railgun/railgun_api.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/echo.x64.o: custom/src/demo/echo.c include/meterpreter_micro.h include/micro_runtime.h
	@mkdir -p build
	$(X64_CC) $(CFLAGS) -c $< -o $@

build/sysinfo.x86.o: stdapi/src/system/sysinfo.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/listing.x86.o: stdapi/src/listing/listing.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/fs_file.x86.o: stdapi/src/fs/file.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/fs_operations.x86.o: stdapi/src/fs/operations.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/fs_hash.x86.o: stdapi/src/fs/hash.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/fs_mount.x86.o: stdapi/src/fs/mount.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/fs_search.x86.o: stdapi/src/fs/search.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/railgun_api.x86.o: stdapi/src/railgun/railgun_api.c include/meterpreter_micro.h include/micro_runtime.h stdapi/include/micro_stdapi.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

build/echo.x86.o: custom/src/demo/echo.c include/meterpreter_micro.h include/micro_runtime.h
	@mkdir -p build
	$(X86_CC) $(CFLAGS) -c $< -o $@

verify: $(OBJECTS)
	@for object in $(X64_OBJECTS); do \
		$(X64_OBJDUMP) -f $$object | grep -q 'file format pe-x86-64'; \
		$(X64_NM) $$object | grep -q ' T micro_init'; \
		$(X64_NM) $$object | grep -q ' T micro_deinit'; \
		if $(X64_NM) -u $$object | grep -q .; then $(X64_NM) -u $$object; exit 1; fi; \
	done
	@for object in $(X86_OBJECTS); do \
		$(X86_OBJDUMP) -f $$object | grep -q 'file format pe-i386'; \
		$(X86_NM) $$object | grep -q ' T _micro_init'; \
		$(X86_NM) $$object | grep -q ' T _micro_deinit'; \
		if $(X86_NM) -u $$object | grep -q .; then $(X86_NM) -u $$object; exit 1; fi; \
	done

clean:
	rm -f $(OBJECTS) build/identity.x64.o build/identity.x86.o
