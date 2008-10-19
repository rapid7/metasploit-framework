#!/usr/bin/env ruby
#
# This tool provides an easy way to see what opcodes are associated with
# certain x86 instructions by making use of nasm if it is installed and
# reachable through the PATH environment variable.
#

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'
require 'rex/ui'

# Check to make sure nasm is installed and reachable through the user's PATH.
begin
	Rex::Assembly::Nasm.check
rescue RuntimeError
	puts "#{$!}"
	exit
end

# Start a pseudo shell and dispatch lines to be assembled and then
# disassembled.
shell = Rex::Ui::Text::PseudoShell.new("%bnasm%c")

shell.run { |line|
	line.gsub!(/(\r|\n)/, '')
	line.gsub!(/\\n/, "\n")	

	break if (line =~ /^(exit|quit)/i)

	begin
		puts(Rex::Assembly::Nasm.disassemble(
			Rex::Assembly::Nasm.assemble(line)))
	rescue RuntimeError
		puts "Error: #{$!}"
	end
}