#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


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

# get in interactive assembler mode
def asm
	puts 'type "exit" or "quit" to quit', 'use ";" for newline', ''
	while (print "asm> " ; $stdout.flush ; l = gets)
		break if %w[quit exit].include? l.chomp
	
		begin
			data = l.gsub(';', "\n")
			next if data.strip.empty?
			data = data.encode
			puts '"' + data.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
		rescue Metasm::Exception => e
			puts "Error: #{e.class} #{e.message}"
		end
	end

	puts
end

if __FILE__ == $0
	asm
end
