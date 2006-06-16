#!/usr/bin/env ruby

##
# Convert a ruby source file from space to tab indentation
# XXX - This program is dumb, it doesn't know about heredocs,
# multiline strings, or anything remotely fancy! 
##

fd    = STDIN
input = ARGV.shift
fd    = File.open(input, "r") if input
tbuff = ''
etabs = 4

# Replace the leading spaces with equivalent tab characters
fd.each_line do |line|
	line.sub!(/^\x20+/) do |m|
		spaces = m.length
		while (spaces % etabs != 0); spaces -= 1; end;
		"\t" * (spaces / etabs)
	end
	tbuff << line
end

puts tbuff
