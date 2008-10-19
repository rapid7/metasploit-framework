#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm'

elf = Metasm::ELF.compile_c(Metasm::Ia32.new, DATA.read)
elf.encode_file('sampelf-c')

__END__
int printf(char *fmt, ...);
void exit(int);
int main(void)
{
	printf("Hello, %s !\n", "world");
	exit(0x28);
}