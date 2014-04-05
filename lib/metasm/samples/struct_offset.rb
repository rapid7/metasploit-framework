#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# This exemple illustrates the usage of the C parser to compute the offset of members of a given structure
# usage: struct_offset.rb <c file> <struct name>
#

require 'metasm'
include Metasm

require 'optparse'
opts = { :hdrs => [], :defs => {}, :path => [], :cpu => 'X86', :offbase => 16 }
OptionParser.new { |opt|
  opt.on('-o outfile') { |f| opts[:outfile] = f }
  opt.on('-H additional_header') { |f| opts[:hdrs] << f }
  opt.on('-I path', '--includepath path') { |f| opts[:path] << f }
  opt.on('-D var') { |f| k, v = f.split('=', 2) ; opts[:defs].update k => (v || '') }
  opt.on('-d') { opts[:offbase] = 10 }
  opt.on('--cpu CpuClass') { |c| opts[:cpu] = c }
  opt.on('--gcc') { opts[:gcc] = true }
  opt.on('--vs', '--visualstudio') { opts[:vs] = true }
}.parse!(ARGV)

cp = Metasm.const_get(opts[:cpu]).new.new_cparser

cp.prepare_gcc if opts[:gcc]
cp.prepare_visualstudio if opts[:vs]

pp = cp.lexer
pp.warn_redefinition = false
pp.include_search_path[0, 0] = opts[:path]
opts[:defs].each { |k, v| pp.define k, v }

cp.parse opts[:hdrs].map { |h| "#include <#{h}>" }.join("\n")

abort 'need source + struct name' unless ARGV.length >= 2

cp.parse_file(ARGV.shift)

$stdout.reopen File.open(opts[:outfile], 'w') if opts[:outfile]

ARGV.each { |structname|
  puts cp.alloc_c_struct(structname)
}
