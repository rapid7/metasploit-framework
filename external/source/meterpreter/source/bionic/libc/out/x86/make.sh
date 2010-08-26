
[ ! -d flood ] && mkdir flood 
rm flood/* 

BAD_FILES=" bcopy_wrapper.o bionic_clone.o bzero_wrapper.o cache_wrapper.o crtbegin_dynamic.o crtbegin_static.o crtend.o dl_iterate_phdr_static.o libc_init_dynamic.o libc_init_static.o memcmp_wrapper.o memcpy_wrapper.o memmove_wrapper.o memset_wrapper.o  res_random.o sha1hash.o socketcalls.o sse2-memset5-atom.o ssse3-memcmp3.o ssse3-memcpy5.o ssse3-strcmp.o strcmp_wrapper.o strncmp_wrapper.o getservent.o "


(cd flood && ar -x ../bionic.a)

for i in $BAD_FILES ; do
	rm flood/$i
done

gcc -nostdinc -nostdlib -shared -o libbionic.so flood/*.o -lgcc

[ ! -f libc.so ] && ln -s ${PWD}/libbionic.so libc.so

rm -rf flood


