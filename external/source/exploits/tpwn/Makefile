all:
	gcc *.m -o tpwn -framework IOKit -framework Foundation -m32 -Wl,-pagezero_size,0 -O3
	strip tpwn
