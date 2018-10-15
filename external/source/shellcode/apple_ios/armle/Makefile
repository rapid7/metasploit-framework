CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -Os -O0
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BIN_IOS=`xcrun --sdk iphoneos -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) $(CFLAGS)
GCC_BASE_IOS=$(GCC_BIN_IOS) $(CFLAGS)
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64
SDK_IOS=`xcrun --sdk iphoneos --show-sdk-path`
GCC_IOS=$(GCC_BASE_IOS) -arch arm64 -isysroot $(SDK_IOS)
GCC_IOS_32=$(GCC_BASE_IOS) -arch armv7 -isysroot $(SDK_IOS)

all: clean main_osx main_ios main_ios32 log

main_osx: main.c
	$(GCC_OSX) -o $@ $^

main_ios: main.c
	$(GCC_IOS) -o $@ $^
	ldid -S main_ios

main_ios32: main.c
	$(GCC_IOS_32) -o $@ $^
	ldid -Sent.xml main_ios32

log: log.c
	$(GCC_IOS_32) -o $@ $^
	ldid -S log

shellcode: main_ios32
	otool -tv main_ios32

flatten: flatten-macho.m
	$(GCC_OSX) -o $@ $^

flatten32: flatten-macho32.m
	$(GCC_OSX) -o $@ $^

main_vm: flatten main_ios
	./flatten main_ios main_vm

main_vm32: flatten32 main_ios32
	./flatten32 main_ios32 main_vm32

log_vm32: flatten32 log
	./flatten32 log log_vm32

install: main_ios32
	ruby met.rb main_ios32
	cp main_ios32.bin ../../../../../data/meterpreter/armle_iphone_stage

clean:
	rm -f *.o main_osx main_ios main_ios32

