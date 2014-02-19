#!/usr/bin/env ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm'
$opts = { :execlass => Metasm::MachO }
load File.join(File.dirname(__FILE__), 'exeencode.rb')

__END__
.text

str db "Hello, World !\n", 0
strlen equ $-str
.align 8

.entrypoint
push strlen
push str
push 1		// stdout
mov eax, 4	// sys_write
push eax
int 80h
add esp, 12

push 0
mov eax, 1	// sys_exit
push eax
int 80h
