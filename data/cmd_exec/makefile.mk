all: show_args_linux show_args_windows
show_args_linux: show_args.c
	cc show_args.c -o show_args_linux
show_args_windows: show_args.c
	x86_64-w64-mingw32-gcc show_args.c -o show_args.exe
