#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# in this exemple we can write a shellcode using a C function
#

require 'metasm'

# load and decode the file
sc = Metasm::Shellcode.new(Metasm::Ia32.new)
sc.parse <<EOS
jmp c_func

some_func:
mov eax, 42
ret
EOS

cp = sc.cpu.new_cparser
cp.parse <<EOS
void some_func(void);
/* __declspec(naked) */ void c_func() {
  int i;
  for (i=0 ; i<10 ; ++i)
    some_func();
}
EOS
asm = sc.cpu.new_ccompiler(cp, sc).compile

sc.parse asm
sc.assemble

sc.encode_file 'shellcode.raw'

puts Metasm::Shellcode.load_file('shellcode.raw', Metasm::Ia32.new).disassemble
