#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Add a file from memory and save it.
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
inc = File.dirname(msfbase) + '/../../..'
$:.unshift(inc)

require 'rex/zip'

# example usage
zip = Rex::Zip::Archive.new
zip.add_file("elite.txt", "A" * 1024)
zip.save_to("lolz.zip")
