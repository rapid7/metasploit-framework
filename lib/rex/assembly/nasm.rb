#!/usr/bin/ruby

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
		if (Rex::FileUtils.find_full_path('nasm') == nil)
			raise RuntimeError, "No nasm installation was found."
		end
	end

	#
	# Assembles the supplied assembly and returns the raw opcodes.
	#
	def self.assemble(assembly)
		check

		# Open the temporary file
		tmp  = Tempfile.new('nasm').path
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
		if (system("nasm -f bin -o #{tmp}.out #{tmp}") == false)
			raise RuntimeError, "Assembler did not complete successfully: #{$?.exitstatus}"
		end

		# Read the assembled text
		rv = ::IO.readlines(tmp + ".out").join('')

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

		tmp = Tempfile.new('nasmout').path

		p = ::IO.popen("echo -ne \"" + Rex::Text.to_hex(raw) + "\" > #{tmp} && ndisasm -u #{tmp}")
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
