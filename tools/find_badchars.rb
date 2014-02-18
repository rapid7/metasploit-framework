#!/usr/bin/env ruby
#
# $Id$
#
# This script is intended to assist an exploit developer in deducing what
# "bad characters" exist for a given input path to a program.
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

OutStatus = "[*] "
OutError  = "[-] "

$args = Rex::Parser::Arguments.new(
  "-b" => [ true, "The list of characters to avoid: '\\x00\\xff'"                      ],
  "-h" => [ false, "Help banner"                                                       ],
  "-i" => [ true, "Read memory contents from the supplied file path"                   ],
  "-t" => [ true, "The format that the memory contents are in (empty to list)"         ])

def usage
  $stderr.puts("\n" + "    Usage: #{File.basename($0)} <options>\n" + $args.usage)
  exit
end

def show_format_list
  $stderr.puts("Supported formats:\n")
  $stderr.puts("  raw      raw binary data\n")
  $stderr.puts("  windbg   output from windbg's \"db\" command\n")
  $stderr.puts("  gdb      output from gdb's \"x/bx\" command\n")
  $stderr.puts("  hex      hex bytes like \"\\xFF\\x41\" or \"eb fe\"\n")
end

def debug_buffer(name, buf)
  str = "\n#{buf.length} bytes of "
  str << name
  str += ":" if buf.length > 0
  str += "\n\n"
  $stderr.puts str
  if buf.length > 0
    $stderr.puts Rex::Text.to_hex_dump(buf)
  end
end


# Input defaults
badchars = ''
fmt      = 'raw'
input    = $stdin

# Output
new_badchars = ''

# Parse the argument and rock that shit.
$args.parse(ARGV) { |opt, idx, val|
  case opt
    when "-i"
      begin
        input = File.new(val)
      rescue
        $stderr.puts(OutError + "Failed to open file #{val}: #{$!}")
        exit
      end
    when "-b"
      badchars = Rex::Text.hex_to_raw(val)
    when "-t"
      if (val =~ /^(raw|windbg|gdb|hex)$/)
        fmt = val
      else
        if val.nil? or val.length < 1
          show_format_list
        else
          $stderr.puts(OutError + "Invalid format: #{val}")
        end
        exit
      end
    when "-h"
      usage
  end
}

if input == $stdin
  $stderr.puts(OutStatus + "Please paste the memory contents in \"" + fmt + "\" format below (end with EOF):\n")
end



# Working data set
from_msf = Rex::Text.charset_exclude(badchars)
from_dbg = ''


# Process the input
from_dbg = input.read
case fmt
  when "raw"
    # this should already be in the correct format :)

  when "windbg"
    translated = ''
    from_dbg.each_line do |ln|
      translated << ln.chomp[10,47].gsub!(/(-| )/, '')
    end
    from_dbg = Rex::Text.hex_to_raw(translated)
    
  when "gdb"
    translated = ''
    from_dbg.each_line do |ln|
      translated << ln.chomp.split(':')[1].gsub!(/0x/, '\x').gsub!(/ /, '')
    end
    from_dbg = Rex::Text.hex_to_raw(translated)

  when "hex"
    translated = ''
    from_dbg.each_line do |ln|
      translated << ln.chomp.gsub!(/ /,'')
    end
    from_dbg = Rex::Text.hex_to_raw(translated)
end



=begin
# Uncomment these to debug stuff ..
debug_buffer("BadChars", badchars)
debug_buffer("memory contents", from_dbg)
debug_buffer("Rex::Text.charset_exclude() output", from_msf)
=end


# Find differences between the two data sets
from_msf = from_msf.unpack('C*')
from_dbg = from_dbg.unpack('C*')
minlen = from_msf.length
minlen = from_dbg.length if from_dbg.length < minlen
(0..(minlen-1)).each do |idx|
  ch1 = from_msf[idx]
  ch2 = from_dbg[idx]
  if ch1 != ch2
    str = "Byte at index 0x%04x differs (0x%02x became 0x%02x)" % [idx, ch1, ch2]
    $stderr.puts OutStatus + str
    new_badchars << ch1
  end
end


# show the results
if new_badchars.length < 1
  $stderr.puts(OutStatus + "All characters matched, no new bad characters discovered.")
else
  $stderr.puts(OutStatus + "Proposed BadChars: \"" + Rex::Text.to_hex(new_badchars) + "\"")
end
