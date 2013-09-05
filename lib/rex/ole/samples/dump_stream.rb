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

if (ARGV.length < 2)
  $stderr.puts "usage: dump_stream <file> <stream>"
  exit(1)
end

document = ARGV.shift
stream = ARGV.shift

if (stg = Rex::OLE::Storage.new(document))
  if (stm = stg.open_stream(stream))
    data = stm.read(stm.length)
    data ||= ""
    $stderr.puts "Successfully opened the \"%s\" stream (%u bytes)" % [stream, data.length]
    $stdout.print data
    stm.close
  else
    $stderr.puts "Unable to open stream: #{stream}"
  end
  stg.close
else
  $stderr.puts "Unable to open storage: #{document}"
end
