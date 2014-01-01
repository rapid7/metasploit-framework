#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', 'lib')))
require 'fastlib'
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'rex'

if (!(length = ARGV.shift))
  $stderr.puts("Usage: #{File.basename($0)} length [set a] [set b] [set c]\n")
  exit
end

# If the user supplied custom sets, use those.  Otherwise, use the default
# sets.
sets = ARGV.length > 0 ? ARGV : Rex::Text::DefaultPatternSets

puts Rex::Text.pattern_create(length.to_i, sets)
