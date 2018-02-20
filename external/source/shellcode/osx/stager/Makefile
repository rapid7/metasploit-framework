CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -Os -O0
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) $(CFLAGS)
GCC_OSX=$(GCC_BASE_OSX) -arch x86_64

all: clean main_osx

main_osx: main.c
	$(GCC_OSX) -o $@ $^

install: main_osx
	cp main_osx ../../../../../data/meterpreter/x64_osx_stage

shellcode: install
	otool -tv main_osx

clean:
	rm -f *.o main_osx

