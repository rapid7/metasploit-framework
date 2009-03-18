BINS=$(subst src/,,$(patsubst %.s,%.bin,$(wildcard src/s*.s)))

all: $(BINS)

%.bin: src/%.s
	nasm -Iinclude/ -f bin -o bin/$@ $<

test: all
	make -C src/test

clean:
	rm -f bin/*.bin; make -C src/test clean
