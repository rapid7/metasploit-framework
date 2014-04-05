#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this script disassembles an executable (elf/pe) and dumps the output
# ruby -h for help
#

require 'metasm'
include Metasm
require 'optparse'

# parse arguments
opts = { :sc_cpu => 'Ia32' }
OptionParser.new { |opt|
  opt.banner = 'Usage: disassemble.rb [options] <executable> [<entrypoints>]'
  opt.on('--no-data', 'do not display data bytes') { opts[:nodata] = true }
  opt.on('--no-data-trace', 'do not backtrace memory read/write accesses') { opts[:nodatatrace] = true }
  opt.on('--debug-backtrace', 'enable backtrace-related debug messages (very verbose)') { opts[:debugbacktrace] = true }
  opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
  opt.on('-o <outfile>', '--output <outfile>', 'save the assembly listing in the specified file (defaults to stdout)') { |h| opts[:outfile] = h }
  opt.on('--cpu <cpu>', 'the CPU class to use for a shellcode (Ia32, X64, ...)') { |c| opts[:sc_cpu] = c }
  opt.on('--exe <exe_fmt>', 'the executable file format to use (PE, ELF, ...)') { |c| opts[:exe_fmt] = c }
  opt.on('--rebase <addr>', 'rebase the loaded file to <addr>') { |a| opts[:rebase] = Integer(a) }
  opt.on('-s <savefile>', 'save the disassembler state after disasm') { |h| opts[:savefile] = h }
  opt.on('-S <addrlist>', '--stop <addrlist>', '--stopaddr <addrlist>', 'do not disassemble past these addresses') { |h| opts[:stopaddr] ||= [] ; opts[:stopaddr] |= h.split ',' }
  opt.on('-P <plugin>', '--plugin <plugin>', 'load a metasm disassembler plugin') { |h| (opts[:plugin] ||= []) << h }
  opt.on('--post-plugin <plugin>', 'load a metasm disassembler plugin after disassembly is finished') { |h| (opts[:post_plugin] ||= []) << h }
  opt.on('-e <code>', '--eval <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
  opt.on('--benchmark') { opts[:benchmark] = true }
  opt.on('--decompile') { opts[:decompile] = true }
  opt.on('--map <mapfile>') { |f| opts[:map] = f }
  opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
  opt.on('--fast', 'use disassemble_fast (no backtracking)') { opts[:fast] = true }
  opt.on('-v', '--verbose') { $VERBOSE = true }
  opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

exename = ARGV.shift

t0 = Time.now if opts[:benchmark]

# load the file
if exename =~ /^live:(.*)/
  raise 'no such live target' if not target = OS.current.find_process($1)
  p target if $VERBOSE
  opts[:sc_cpu] = eval(opts[:sc_cpu]) if opts[:sc_cpu] =~ /[.(\s:]/
  opts[:sc_cpu] = Metasm.const_get(opts[:sc_cpu]) if opts[:sc_cpu].kind_of(::String)
  opts[:sc_cpu] = opts[:sc_cpu].new if opts[:sc_cpu].kind_of?(::Class)
  exe = Shellcode.decode(target.memory, opts[:sc_cpu])
else
  opts[:sc_cpu] = eval(opts[:sc_cpu]) if opts[:sc_cpu] =~ /[.(\s:]/
  opts[:exe_fmt] = eval(opts[:exe_fmt]) if opts[:exe_fmt] =~ /[.(\s:]/
  if opts[:exe_fmt].kind_of?(::String)
    exefmt = opts[:exe_fmt] = Metasm.const_get(opts[:exe_fmt])
  else
    exefmt = opts[:exe_fmt] || AutoExe.orshellcode {
      opts[:sc_cpu] = Metasm.const_get(opts[:sc_cpu]) if opts[:sc_cpu].kind_of?(::String)
      opts[:sc_cpu] = opts[:sc_cpu].new if opts[:sc_cpu].kind_of?(::Class)
      opts[:sc_cpu]
    }
  end
  exefmt = exefmt.withcpu(opts[:sc_cpu]) if exefmt.kind_of?(::Class) and exefmt.name.to_s.split('::').last == 'Shellcode'
  exe = exefmt.decode_file(exename)
  exe.disassembler.rebase(opts[:rebase]) if opts[:rebase]
  if opts[:autoload]
    basename = exename.sub(/\.\w\w?\w?$/, '')
    opts[:map] ||= basename + '.map' if File.exist?(basename + '.map')
    opts[:cheader] ||= basename + '.h' if File.exist?(basename + '.h')
    (opts[:plugin] ||= []) << (basename + '.rb') if File.exist?(basename + '.rb')
  end
end
# set options
dasm = exe.disassembler
makeint = lambda { |addr|
  case addr
  when /^[0-9].*h/; addr.to_i(16)
  when /^[0-9]/; Integer(addr)
  else dasm.normalize(addr)
  end
}
dasm.load_map opts[:map] if opts[:map]
dasm.parse_c_file opts[:cheader] if opts[:cheader]
dasm.backtrace_maxblocks_data = -1 if opts[:nodatatrace]
dasm.debug_backtrace = true if opts[:debugbacktrace]
opts[:stopaddr].to_a.each { |addr| dasm.decoded[makeint[addr]] = true }
opts[:plugin].to_a.each { |p|
  begin
    dasm.load_plugin p
  rescue ::Exception
    puts "Error with plugin #{p}: #{$!.class} #{$!}"
  end
}
opts[:hookstr].to_a.each { |f| eval f }

t1 = Time.now if opts[:benchmark]
# do the work
begin
  method = opts[:fast] ? :disassemble_fast_deep : :disassemble
  if ARGV.empty?
    exe.send(method)
  else
    exe.send(method, *ARGV.map { |addr| makeint[addr] })
  end
rescue Interrupt
  puts $!, $!.backtrace
end
t2 = Time.now if opts[:benchmark]

if opts[:decompile]
  dasm.save_file(opts[:savefile]) if opts[:savefile]
  dasm.decompile(*dasm.entrypoints)
  tdc = Time.now if opts[:benchmark]
end

opts[:post_plugin].to_a.each { |p|
  begin
    dasm.load_plugin p
  rescue ::Exception
    puts "Error with plugin #{p}: #{$!.class} #{$!}"
  end
}

dasm.save_file(opts[:savefile]) if opts[:savefile]

# output
if opts[:outfile]
  File.open(opts[:outfile], 'w') { |fd|
    fd.puts dasm.c_parser if opts[:decompile]
    fd.puts "#if 0" if opts[:decompile]
    dasm.dump(!opts[:nodata]) { |l| fd.puts l }
    fd.puts "#endif" if opts[:decompile]
  }
elsif not opts[:savefile]
  if opts[:decompile]
    puts dasm.c_parser
  else
    dasm.dump(!opts[:nodata])
  end
end

t3 = Time.now if opts[:benchmark]

todate = lambda { |f|
  if f > 5400
    "#{f.to_i/3600}h#{(f.to_i%3600)/60}mn"
  elsif f > 90
    "#{f.to_i/60}mn#{f.to_i%60}s"
  else
    "#{'%.02f' % f}s"
  end
}

puts "durations\n load   #{todate[t1-t0]}\n dasm   #{todate[t2-t1]}#{"\n decomp "+todate[tdc-t2] if tdc}\n output #{todate[t3-(tdc||t2)]}\n total  #{todate[t3-t0]}" if opts[:benchmark]
