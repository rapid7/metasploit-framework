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
  $stderr.puts "usage: make_ole <file>"
  exit(1)
end

document = ARGV.shift

if (stg = Rex::OLE::Storage.new(document, Rex::OLE::STGM_WRITE))
  if (stm = stg.create_stream("testing"))
    stm << "A" * 1024
    stm.close
  end
  stg.close
end
