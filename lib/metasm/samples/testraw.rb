#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



# usage: test.rb < source.asm

require 'metasm'


dump = ARGV.delete '--dump'

source = ARGF.read

cpu = Metasm::Ia32.new
shellcode = Metasm::Shellcode.assemble(cpu, source).encode_string
shellstring = shellcode.unpack('C*').map { |b| '\\x%02x' % b }.join

if dump
  puts shellstring
  exit
end

File.open('test-testraw.c', 'w') { |fd|
  fd.puts <<EOS
unsigned char sc[] = "#{shellstring}";
int main(void)
{
  ((void (*)())sc)();
  return 42;
}
EOS
}

system 'gcc -W -Wall -o test-testraw test-testraw.c'
system 'chpax -psm test-testraw'

puts "running"
system './test-testraw'
puts "done"
#File.unlink 'test-testraw'
File.unlink 'test-testraw.c'
