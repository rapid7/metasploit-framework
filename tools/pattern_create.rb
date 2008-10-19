#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'

if (!(length = ARGV.shift))
	$stderr.puts("Usage: #{File.basename($0)} length [set a] [set b] [set c]\n")
	exit
end

# If the user supplied custom sets, use those.  Otherwise, use the default
# sets.
sets = ARGV.length > 0 ? ARGV : Rex::Text::DefaultPatternSets

puts Rex::Text.pattern_create(length.to_i, sets)