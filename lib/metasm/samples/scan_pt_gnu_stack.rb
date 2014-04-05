#!/usr/bin/env ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this script scans directories recursively for ELF files which have a PT_GNU_STACK rwe or absent
# usage : scan_pt_gnu_stack.rb <dir> [<dir>]
#

require 'metasm'

def _puts(a)
  puts a.to_s.ljust(60)
end
def _printadv(a)
  $stderr.print a.to_s.ljust(60)[-60, 60] + "\r"
end

# the recursive scanning procedure
iter = lambda { |f|
  if File.symlink? f
  elsif File.directory? f
    # show where we are & recurse
    _printadv f
    Dir[ File.join(f, '*') ].each { |ff|
 			iter[ff]
 		}
  else
    # interpret any file as a ELF
    begin
      elf = Metasm::ELF.decode_file_header(f)
      next if not elf.segments or elf.header.type == 'REL'
      seg = elf.segments.find { |seg_| seg_.type == 'GNU_STACK' }
      if not seg
        _puts "PT_GNU_STACK absent : #{f}"
      elsif seg.flags.include? 'X'
        _puts "PT_GNU_STACK RWE :    #{f}"
      else
        _puts "#{f} : #{seg.inspect}" if $VERBOSE
      end
    rescue
      # the file is not a valid ELF
      _puts "E: #{f} #{$!}" if $VERBOSE
    end
  end
}

# go
ARGV.each { |dir| iter[dir] }

_printadv ''
