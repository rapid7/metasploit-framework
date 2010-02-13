#!/usr/bin/env ruby
#
# This tool provides an easy way to see what opcodes are associated with
# certain x86 instructions by making use of Metasm!
#

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'
require 'rex/ui'
require 'metasm'


class String
	@@cpu = Metasm::Ia32.new
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
