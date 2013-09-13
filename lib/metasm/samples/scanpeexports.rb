#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this script scans a directory for PE files which export a given symbol name (regexp case-insensitive)
# usage : ruby scanpeexports.rb <dir> <pattern>
#

require 'metasm'

if not base = ARGV.shift
  puts 'base dir ?'
  base = gets.chomp
end
if not pat = ARGV.shift
  puts 'pattern ?'
  pat = gets.chomp
  puts 'searching...'
end

def _puts(a)
  puts a.to_s.ljust(60)
end
def _printadv(a)
  $stderr.print a.to_s.ljust(60)[-60, 60] + "\r"
end

# the recursive scanning procedure
iter = lambda { |f, match|
  if File.directory? f
    # show where we are & recurse
    _printadv f
    Dir[ File.join(f, '*') ].each { |ff|
 			iter[ff, match]
 		}
  else
    # interpret any file as a PE
    begin
      pe = Metasm::PE.decode_file_header(f)
      pe.decode_exports
      next if not pe.export
      # scan the export directory for the symbol pattern, excluding forwarders
      pe.export.exports.each { |exp|
        if exp.name =~ /#{match}/i and not exp.forwarder_lib
          _puts f + " : " + exp.name
        end
      }
    rescue
      # the file is not a valid PE
    end
  end
}

# go
iter[base, pat]

if RUBY_PLATFORM =~ /win32/i
  _puts "press [enter] to exit"
  gets
end
