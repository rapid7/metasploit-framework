#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'

if ARGV.length < 2
	$stderr.puts("Usage: #{File.basename($0)} buffer [text/integer]")
end

buffer = ARGV.shift
value  = ARGV.shift
value  = value.hex if (value.length >= 8 and value.hex > 0)

puts Rex::Text.pattern_offset(buffer, value)
