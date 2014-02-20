#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this script takes a list of dll filenames as arguments, and outputs each lib export
# libname, followed by the list of the exported symbol names, in a format usable
# by the PE class autoimport functionnality (see metasm/os/windows.rb)
#

require 'metasm'

ARGV.each { |f|
  pe = Metasm::PE.decode_file_header(f) rescue next
  pe.decode_exports
  next if not pe.export or not pe.export.libname
  puts pe.export.libname.sub(/\.dll$/i, '')
  line = ''
  pe.export.exports.each { |e|
    next if not e.name
    # next if not e.target	# allow forwarders ? (may change name)
    e = ' ' << e.name
    if line.length + e.length >= 160
      puts line
      line = ''
    end
    line << e
  }
  puts line if not line.empty?
}
