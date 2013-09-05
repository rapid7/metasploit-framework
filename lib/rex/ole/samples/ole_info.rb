#!/usr/bin/env ruby
# -*- coding: binary -*-

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
path = File.expand_path(File.dirname(msfbase))
path += "/../../../"
$:.unshift(path)

require 'rex/ole'

if (ARGV.length < 1)
  $stderr.puts "usage: ole_info <file>"
  exit(1)
end

document = ARGV.shift

if (stg = Rex::OLE::Storage.new(document))
  puts stg.inspect
  stg.close
end
