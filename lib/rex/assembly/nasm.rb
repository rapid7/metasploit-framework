#!/usr/bin/env ruby

require 'tempfile'
require 'rex/file'
require 'rex/text'

module Rex
module Assembly

###
#
# This class uses nasm to assemble and disassemble stuff.
#
###
class Nasm

	#
	# Ensures that the nasm environment is sane.
	#
	def self.check
		path = 
			Rex::FileUtils.find_full_path('nasm')      ||
			Rex::FileUtils.find_full_path('nasm.exe')  ||
			Rex::FileUtils.find_full_path('nasmw.exe') ||
			raise(RuntimeError, "No nasm installation was found.")
	end

	#
	# Assembles the supplied assembly and returns the raw opcodes.
	#
	def self.assemble(assembly)
		check

		# Open the temporary file
		tmp  = Tempfile.new('nasmXXXX').path
		file = File.new(tmp, "w")

		# Write the assembly data to a file
		begin
			file.write("BITS 32\n" + assembly)
			file.close
			file = nil
		ensure
			file.close if (file)
		end

		# Run nasm
		if (system("nasm -f bin -o '#{tmp}.out' '#{tmp}'") == false)
			raise RuntimeError, "Assembler did not complete successfully: #{$?.exitstatus}"
		end

		# Read the assembled text
		rv = ::IO.read(tmp + ".out")

		# Remove temporary files
		File.unlink(tmp)
		File.unlink(tmp + ".out")

		rv
	end

	#
	# Disassembles the supplied raw opcodes
	#
	def self.disassemble(raw)
		check

		# Race condition?! You bet!
		tmp = Tempfile.new('nasmout').path
		File.open(tmp, "wb") { |f| f.write(raw) }

		p = ::IO.popen("ndisasm -u '#{tmp}'")
		o = ''

		begin
			until p.eof?
				o += p.read
			end
		ensure
			p.close
		end

		File.unlink(tmp)

		o
	end

end

end
end
