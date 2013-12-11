#!/usr/bin/env ruby
#
# $Id$
#
# This tool provides an easy way to see what opcodes are associated with
# certain x86 instructions by making use of Metasm!
#
#
# $Revision$
#

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'
require 'rex/ui'
require 'metasm'

#PowerPC, seems broken for now in metasm
#@Arch = ['Ia32','MIPS','PowerPC','ARM','X86_64']
@Arch = ['Ia32','MIPS','ARM','X86_64']

def usage
  $stderr.puts("\nUsage: #{$0} <options>\n" + $args.usage)
  exit
end
    
$args = Rex::Parser::Arguments.new(
  "-a" => [ true, "The architecture to encode as (#{@Arch.sort.collect{|a| a + ', ' }.join.gsub(/\, $/,'')})"],
  "-h" => [ false, "Display this help information"	])

$args.parse(ARGV) { |opt, idx, val|
  case opt
  when "-a"
    found = nil
    @Arch.each { |a|
      if val.downcase == a.downcase
        String.class_eval("@@cpu = Metasm::#{a}.new")
        found = true
      end
    }
    usage if not found

  when "-h"
    usage
  else
    usage
  end
}

class String
  @@cpu ||= Metasm::Ia32.new
  class << self
    def cpu()   @@cpu   end
    def cpu=(c) @@cpu=c end
  end

  # encodes the current string as a Shellcode, returns the resulting EncodedData
  def encode_edata
    s = Metasm::Shellcode.assemble @@cpu, self
    s.encoded
  end

  # encodes the current string as a Shellcode, returns the resulting binary String
  # outputs warnings on unresolved relocations
  def encode
    ed = encode_edata
    if not ed.reloc.empty?
      puts 'W: encoded string has unresolved relocations: ' + ed.reloc.map { |o, r| r.target.inspect }.join(', ')
    end
    ed.fill
    ed.data
  end

  # decodes the current string as a Shellcode, with specified base address
  # returns the resulting Disassembler
  def decode_blocks(base_addr=0, eip=base_addr)
    sc = Metasm::Shellcode.decode(self, @@cpu)
    sc.base_addr = base_addr
    sc.disassemble(eip)
  end

  # decodes the current string as a Shellcode, with specified base address
  # returns the asm source equivallent
  def decode(base_addr=0, eip=base_addr)
    decode_blocks(base_addr, eip).to_s
  end
end



# Start a pseudo shell and dispatch lines to be assembled and then
# disassembled.
shell = Rex::Ui::Text::PseudoShell.new("%bldmetasm%clr")
shell.init_ui(Rex::Ui::Text::Input::Stdio.new, Rex::Ui::Text::Output::Stdio.new)

puts 'type "exit" or "quit" to quit', 'use ";" or "\\n" for newline', ''

shell.run { |l|
  l.gsub!(/(\r|\n)/, '')
  l.gsub!(/\\n/, "\n")	
  l.gsub!(';', "\n")

  break if %w[quit exit].include? l.chomp
  next if l.strip.empty?

  begin
    l = l.encode
    puts '"' + l.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
  rescue Metasm::Exception => e
    puts "Error: #{e.class} #{e.message}"
  end
}
