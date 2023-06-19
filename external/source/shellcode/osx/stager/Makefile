CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -Os -O0
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) $(CFLAGS)
GCC_OSX_X64=$(GCC_BASE_OSX) -arch x86_64
GCC_OSX_AARCH64=$(GCC_BASE_OSX) -arch arm64

all: clean x64_osx_stage aarch64_osx_stage

debug: clean x64_osx_stage_debug aarch64_osx_stage_debug

x64_osx_stage: main.c
	$(GCC_OSX_X64) -o $@ $^

x64_osx_stage_debug: main.c
	$(GCC_OSX_X64) -D DEBUG -o $@ $^ printf/printf.c

aarch64_osx_stage: main.c
	$(GCC_OSX_AARCH64) -o $@ $^

aarch64_osx_stage_debug: main.c
	$(GCC_OSX_AARCH64) -D DEBUG -o $@ $^ printf/printf.c

install: x64_osx_stage aarch64_osx_stage
	cp x64_osx_stage ../../../../../data/meterpreter/x64_osx_stage
	cp aarch64_osx_stage ../../../../../data/meterpreter/aarch64_osx_stage

install_debug: x64_osx_stage_debug aarch64_osx_stage_debug
	cp x64_osx_stage_debug ../../../../../data/meterpreter/x64_osx_stage
	cp aarch64_osx_stage_debug ../../../../../data/meterpreter/aarch64_osx_stage

x64_shellcode: install
	otool -tv x64_osx_stage

aarch64_shellcode: install
	otool -tv aarch64_osx_stage

clean:
	rm -f *.o x64_osx_stage aarch64_osx_stage x64_osx_stage_debug aarch64_osx_stage_debug

