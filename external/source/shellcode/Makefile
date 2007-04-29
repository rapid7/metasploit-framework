MODS=linux/ia32 bsd/ia32 bsdi/ia32

all:
	for i in ${MODS}; do cd $$i && make && cd ../.. ; done

clean:
	for i in ${MODS}; do cd $$i && make clean && cd ../.. ; done
