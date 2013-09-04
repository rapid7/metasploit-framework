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

msfbase = __FILE__
while File.symlink?(msfbase)
	msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

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
