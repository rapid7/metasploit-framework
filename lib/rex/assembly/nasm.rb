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

	@@nasm_path    = 'nasm'
	@@ndisasm_path = 'ndisasm'
	
	#
	# Ensures that the nasm environment is sane.
	#
	def self.check
		@@nasm_path = 
			Rex::FileUtils.find_full_path('nasm')      ||
			Rex::FileUtils.find_full_path('nasm.exe')  ||
			Rex::FileUtils.find_full_path('nasmw.exe') ||
			raise(RuntimeError, "No nasm installation was found.")
		
		@@ndisasm_path = 
			Rex::FileUtils.find_full_path('ndisasm')      ||
			Rex::FileUtils.find_full_path('ndisasm.exe')  ||
			Rex::FileUtils.find_full_path('ndisasmw.exe') ||
			raise(RuntimeError, "No ndisasm installation was found.")			
	end

	#
	# Assembles the supplied assembly and returns the raw opcodes.
	#
	def self.assemble(assembly)
		check

		# Open the temporary file
		tmp = Tempfile.new('nasmXXXX')
		tpath = tmp.path
		opath = tmp.path + '.out'

		# Write the assembly data to a file
		tmp.write("BITS 32\n" + assembly)
		tmp.flush()
		tmp.seek(0)

		# Run nasm
		if (system(@@nasm_path, '-f', 'bin', '-o', opath, tpath) == false)
			raise RuntimeError, "Assembler did not complete successfully: #{$?.exitstatus}"
		end

		# Read the assembled text
		rv = ::IO.read(opath)

		# Remove temporary files
		File.unlink(opath)
		File.unlink(tpath)
		tmp.close

		rv
	end

	#
	# Disassembles the supplied raw opcodes
	#
	def self.disassemble(raw)
		check
		
		tmp = Tempfile.new('nasmout')
		tfd = File.open(tmp.path, "wb")
		
		tfd.write(raw)
		tfd.flush()
		tfd.close

		p = ::IO.popen("\"#{@@ndisasm_path}\" -u \"#{tmp.path}\"")
		o = ''

		begin
			until p.eof?
				o += p.read
			end
		ensure
			p.close
		end

		tmp.close

		o
	end

end

end
end