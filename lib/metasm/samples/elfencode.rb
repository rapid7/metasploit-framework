#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/elf_encode'

elf = Metasm::ELF.assemble(Metasm::Ia32.new, DATA.read)

# add a PT_GNU_STACK RW segment descriptor
ptgnustack = Metasm::ELF::Segment.new
ptgnustack.memsize = %w[R W]
ptgnustack.type = 'PT_GNU_STACK'
elf.segments << ptgnustack

elf.encode_file('testelf')

__END__
.interp '/lib/ld-linux.so.2'

sys_write equ 4
sys_exit  equ 1
stdout    equ 1

syscall macro nr
 mov eax, nr // the syscall number goes in eax
 int 80h
endm

write macro(string, stringlen)
 mov ebx, stdout
 mov ecx, string
 mov edx, stringlen
 syscall(sys_write)
endm

.text
.data
toto:
# if 0 + 1 > 0
 db "toto\n"
#elif defined(STR)
 db STR
#else
 db "lala\n"
#endif
toto_len equ $-toto

convtab db '0123456789ABCDEF'
outbuf	db '0x', 8 dup('0'), '\n'

.text
pre_start:
 write(toto, toto_len)
 ret

start:
.import 'libc.so.6' '_exit', pltexit
.import 'libc.so.6' 'printf', pltprintf

 push dword ptr [printf]
 call hexdump

 call pushstr
 db "kikoolol\n\0"
pushstr:
 push esp
 call pltprintf
 add esp, 8

 push dword ptr [printf]
 call hexdump

 push 0
 call pltexit

hexdump:
 mov ebx, convtab
 mov edx, [esp+4]
 mov ecx, 8
 mov ebp, outbuf+1
 std

charloop:
 mov eax, edx
 and eax, 0xf
 xlat
 mov [ebp+ecx], al
 shl edx, 4
 loop charloop

 cld
 write(outbuf, 11)

 ret 4
