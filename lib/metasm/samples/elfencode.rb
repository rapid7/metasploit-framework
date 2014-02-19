#!/usr/bin/env ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm'
$opts = { :execlass => Metasm::ELF, :exetype => :lib }
load File.join(File.dirname(__FILE__), 'exeencode.rb')

__END__
.pt_gnu_stack rw
// .nointerp    // to disable the dynamic section, eg for stuff with int80 only
.text
.entrypoint
push bla
push fmt
call printf
push 0
call exit

.data
bla db "world", 0
fmt db "Hello, %s !\n", 0
