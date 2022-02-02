CXXFLAGS := -fno-stack-protector -Os -DCURRENT_DIR=\"$(CURDIR)\" -std=c++17 -shared -fpic

all: loader.bin

loader.bin: libloader.dylib
	./make.py $^ $@

libloader.dylib: loader.cpp entry.s
	$(CXX) $(CXXFLAGS)  $< -o $@

clean:
	rm loader.bin libloader.dylib

.PHONY: all clean
