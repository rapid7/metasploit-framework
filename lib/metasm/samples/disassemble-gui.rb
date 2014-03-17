#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this script disassembles an executable (elf/pe) using the GTK front-end
# use live:bla to open a running process whose filename contains 'bla'
#
# key binding (non exhaustive):
#  Enter to follow a label (the current hilighted word)
#  Esc to return to the previous position
#  Space to switch between listing and graph views
#  Tab to decompile (on already disassembled code)
#  'c' to start disassembling from the cursor position
#  'g' to go to a specific address (label/042h)
#  'l' to list known labels
#  'f' to list known functions
#  'x' to list xrefs to current address
#  'n' to rename a label (current word or current address)
#  ctrl+'r' to run arbitrary ruby code in the context of the Gui objet (access to 'dasm', 'curaddr')
#  ctrl+mousewheel to zoom in graph view ; also doubleclick on the background ('fit to window'/'reset zoom')
#

require 'metasm'
require 'optparse'

$VERBOSE = true

# parse arguments
opts = { :sc_cpu => 'Ia32' }
OptionParser.new { |opt|
  opt.banner = 'Usage: disassemble-gtk.rb [options] <executable> [<entrypoints>]'
  opt.on('--no-data-trace', 'do not backtrace memory read/write accesses') { opts[:nodatatrace] = true }
  opt.on('--debug-backtrace', 'enable backtrace-related debug messages (very verbose)') { opts[:debugbacktrace] = true }
  opt.on('-P <plugin>', '--plugin <plugin>', 'load a metasm disassembler/debugger plugin') { |h| (opts[:plugin] ||= []) << h }
  opt.on('-e <code>', '--eval <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
  opt.on('--map <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map] = f }
  opt.on('--fast', 'dasm cli args with disassemble_fast_deep') { opts[:fast] = true }
  opt.on('--decompile') { opts[:decompile] = true }
  opt.on('--gui <gtk|win32|qt>') { |g| require 'metasm/gui/' + g }
  opt.on('--cpu <cpu>', 'the CPU class to use for a shellcode (Ia32, X64, ...)') { |c| opts[:sc_cpu] = c }
  opt.on('--exe <exe_fmt>', 'the executable file format to use (PE, ELF, ...)') { |c| opts[:exe_fmt] = c }
  opt.on('--rebase <addr>', 'rebase the loaded file to <addr>') { |a| opts[:rebase] = Integer(a) }
  opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
  opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
  opt.on('-v', '--verbose') { $VERBOSE = true }	# default
  opt.on('-q', '--no-verbose') { $VERBOSE = false }
  opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

case exename = ARGV.shift
when /^live:(.*)/
  t = $1
  t = t.to_i if $1 =~ /^[0-9]+$/
  os = Metasm::OS.current
  raise 'no such target' if not target = os.find_process(t) || os.create_process(t)
  p target if $VERBOSE
  w = Metasm::Gui::DbgWindow.new(target.debugger, "#{target.pid}:#{target.modules[0].path rescue nil} - metasm debugger")
  dbg = w.dbg_widget.dbg
when /^(tcp:|udp:)?..+:/
  dbg = Metasm::GdbRemoteDebugger.new(exename, opts[:sc_cpu])
  w = Metasm::Gui::DbgWindow.new(dbg, "remote - metasm debugger")
else
  w = Metasm::Gui::DasmWindow.new("#{exename + ' - ' if exename}metasm disassembler")
  if exename
    exe = w.loadfile(exename, opts[:sc_cpu], opts[:exe_fmt])
    exe.disassembler.rebase(opts[:rebase]) if opts[:rebase]
    if opts[:autoload]
      basename = exename.sub(/\.\w\w?\w?$/, '')
      opts[:map] ||= basename + '.map' if File.exist?(basename + '.map')
      opts[:cheader] ||= basename + '.h' if File.exist?(basename + '.h')
      (opts[:plugin] ||= []) << (basename + '.rb') if File.exist?(basename + '.rb')
    end
  end
end

ep = ARGV.map { |arg| (?0..?9).include?(arg[0]) ? Integer(arg) : arg }

if exe
  dasm = exe.init_disassembler

  dasm.load_map opts[:map] if opts[:map]
  dasm.parse_c_file opts[:cheader] if opts[:cheader]
  dasm.backtrace_maxblocks_data = -1 if opts[:nodatatrace]
  dasm.debug_backtrace = true if opts[:debugbacktrace]
  dasm.disassemble_fast_deep(*ep) if opts[:fast]
  dasm.callback_finished = lambda { w.dasm_widget.focus_addr w.dasm_widget.curaddr, :decompile ; dasm.decompiler.finalize } if opts[:decompile]
elsif dbg
  dbg.load_map opts[:map] if opts[:map]
  opts[:plugin].to_a.each { |p| dbg.load_plugin(p) }
end
if dasm
  w.display(dasm, ep)
  opts[:plugin].to_a.each { |p| dasm.load_plugin(p) }
end

opts[:hookstr].to_a.each { |f| eval f }

Metasm::Gui.main
