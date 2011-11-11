#!/usr/bin/env ruby
#
# $Id$
#
# This tool provides an easy way to see what opcodes are associated with
# certain x86 instructions by making use of nasm if it is installed and
# reachable through the PATH environment variable.
#
# $Revision$
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

bits = ARGV.length > 0 ? ARGV[0].to_i : 32
if ! [16, 32, 64].include?(bits) then
    puts "#{bits} bits not supported"
    exit 1
end

# Start a pseudo shell and dispatch lines to be assembled and then
# disassembled.
shell = Rex::Ui::Text::PseudoShell.new("%bldnasm%clr")
shell.init_ui(Rex::Ui::Text::Input::Stdio.new, Rex::Ui::Text::Output::Stdio.new)

shell.run { |line|
	line.gsub!(/(\r|\n)/, '')
	line.gsub!(/\\n/, "\n")	

	break if (line =~ /^(exit|quit)/i)

	begin
		puts(Rex::Assembly::Nasm.disassemble(
			Rex::Assembly::Nasm.assemble(line, bits), bits))
	rescue RuntimeError
		puts "Error: #{$!}"
	end
}
