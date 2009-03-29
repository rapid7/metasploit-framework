#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
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
opts = {}
OptionParser.new { |opt|
	opt.banner = 'Usage: disassemble.rb [options] <executable> [<entrypoints>]'
	opt.on('--no-data', 'do not display data bytes') { opts[:nodata] = true }
	opt.on('--no-data-trace', 'do not backtrace memory read/write accesses') { opts[:nodatatrace] = true }
	opt.on('--debug-backtrace', 'enable backtrace-related debug messages (very verbose)') { opts[:debugbacktrace] = true }
	opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
	opt.on('-o <outfile>', '--output <outfile>', 'save the assembly listing in the specified file (defaults to stdout)') { |h| opts[:outfile] = h }
	opt.on('-s <addrlist>', '--stop <addrlist>', '--stopaddr <addrlist>', 'do not disassemble past these addresses') { |h| opts[:stopaddr] ||= [] ; opts[:stopaddr] |= h.split ',' }
	opt.on('--custom <hookfile>', 'eval a ruby script hookfile') { |h| (opts[:hookfile] ||= []) << h }
	opt.on('--eval <code>', '-e <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
	opt.on('--benchmark') { opts[:benchmark] = true }
	opt.on('--decompile') { opts[:decompile] = true }
	opt.on('-v', '--verbose') { $VERBOSE = true }
	opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

exename = ARGV.shift

t0 = Time.now if opts[:benchmark]

# load the file
if exename =~ /^live:(.*)/
	raise 'no such live target' if not target = OS.current.find_process($1)
	p target if $VERBOSE
	exe = Shellcode.decode(target.memory, Ia32.new)
else
	exe = AutoExe.orshellcode(Ia32.new).decode_file(exename)
end
# set options
dasm = exe.init_disassembler
makeint = lambda { |addr|
	case addr
	when /^[0-9].*h/; addr.to_i(16)
	when /^[0-9]/; Integer(addr)
	else dasm.normalize(addr)
	end
}
dasm.parse_c_file opts[:cheader] if opts[:cheader]
dasm.backtrace_maxblocks_data = -1 if opts[:nodatatrace]
dasm.debug_backtrace = true if opts[:debugbacktrace]
opts[:stopaddr].to_a.each { |addr| dasm.decoded[makeint[addr]] = true }
opts[:hookfile].to_a.each { |f| eval File.read(f) }
opts[:hookstr].to_a.each { |f| eval f }

t1 = Time.now if opts[:benchmark]
# do the work
begin
	if ARGV.empty?
		exe.disassemble
	else
		exe.disassemble(*ARGV.map { |addr| makeint[addr] })
	end
rescue Interrupt
	puts $!, $!.backtrace
end
t2 = Time.now if opts[:benchmark]

if opts[:decompile]
	dcmp = Decompiler.new(dasm)
	dasm.entrypoints.each { |ep|
		dcmp.decompile_func(ep)
	}
	tdc = Time.now if opts[:benchmark]
end

# output
if opts[:outfile]
	File.open(opts[:outfile], 'w') { |fd|
		fd.puts dcmp.c_parser if opts[:decompile]
		dasm.dump(!opts[:nodata]) { |l| fd.puts l }
	}
else
	if opts[:decompile]
		puts dcmp.c_parser
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
