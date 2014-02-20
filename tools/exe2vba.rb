#!/usr/bin/env ruby
#
# $Id$
#
# This script converts an EXE to a VBA script for Word/Excel
# Credit to PriestMaster for the original C code
#
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
require 'msf/base'

def usage
  $stderr.puts("    Usage: #{$0} [exe] [vba]\n")
  exit
end

exe = ARGV.shift
vba = ARGV.shift

if (not (exe and vba))
  usage
end

out = File.new(vba, "w")
inp = File.open(exe, "rb")

dat = ""
while(buf = inp.read(8192))
  dat << buf
end

out.write(Msf::Util::EXE.to_exe_vba(dat))
out.close
inp.close

$stderr.puts "[*] Converted #{dat.length} bytes of EXE into a VBA script"
