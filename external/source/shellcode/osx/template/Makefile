.PHONY: templates
CFLAGS=-fno-stack-protector -fomit-frame-pointer -fno-exceptions -fPIC -Os -O0
GCC_BIN_OSX=`xcrun --sdk macosx -f gcc`
GCC_BASE_OSX=$(GCC_BIN_OSX) $(CFLAGS)
GCC_OSX_X64=$(GCC_BASE_OSX) -arch x86_64
GCC_OSX_AARCH64=$(GCC_BASE_OSX) -arch arm64

all: templates

template_aarch64_darwin: template_aarch64_darwin.c
	$(GCC_OSX_AARCH64) -o $@ $^
	strip $@

templates: template_aarch64_darwin

install: templates
	cp template_aarch64_darwin ../../../../../data/templates/template_aarch64_darwin.bin

clean:
	rm -f template_aarch64_darwin
