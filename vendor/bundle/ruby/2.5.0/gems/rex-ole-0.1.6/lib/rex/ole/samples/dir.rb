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
  $stderr.puts "usage: dir <file>"
  exit(1)
end

document = ARGV.shift


# recursive printer :)
def show_entries(ent, spaces=0)
  spstr = " " * spaces

  puts "%s + #{ent.name}" % spstr
  ent.each { |el|
    show_entries(el, spaces+2)
  }
end

if (stg = Rex::OLE::Storage.new(document))
  show_entries(stg)
  stg.close
end
