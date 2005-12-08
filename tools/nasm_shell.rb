#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'
require 'rex/ui'

shell = Rex::Ui::Text::PseudoShell.new("%bnasm%c")

shell.run { |line|
	line.gsub!(/(\r|\n)/, '')
	line.gsub!(/\\n/, "\n")	

	break if (line =~ /^(exit|quit)/i)

	puts(Rex::Assembly::Nasm.disassemble(
		Rex::Assembly::Nasm.assemble(line)))
}
