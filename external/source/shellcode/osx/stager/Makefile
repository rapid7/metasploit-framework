CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -O0
SDK=`xcrun --sdk iphoneos --show-sdk-path`
GCC_BIN=`xcrun --sdk iphoneos -f gcc`
GCC_BASE=$(GCC_BIN) $(CFLAGS) -Wimplicit -isysroot $(SDK)
GCC=$(GCC_BASE) -arch arm64

SDK_OSX=`xcrun --sdk macosx --show-sdk-path`
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) -Os $(CFLAGS) 
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64

all: clean main_osx

main_osx: main.c
	$(GCC_OSX) -o $@ $^

install: main_osx
	cp main_osx ../../../../../data/meterpreter/x64_osx_stage

shellcode: install
	otool -tv main_osx

clean:
	rm -f *.o main_ios main_osx

