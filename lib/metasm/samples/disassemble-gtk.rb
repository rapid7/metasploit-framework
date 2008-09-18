#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script disassembles an executable (elf/pe) using the GTK front-end
#

require 'metasm'
require 'optparse'
require 'metasm/gui/gtk'

# parse arguments
opts = {}
OptionParser.new { |opt|
	opt.banner = 'Usage: disassemble-gtk.rb [options] <executable> [<entrypoints>]'
	opt.on('--no-data-trace', 'do not backtrace memory read/write accesses') { opts[:nodatatrace] = true }
	opt.on('--debug-backtrace', 'enable backtrace-related debug messages (very verbose)') { opts[:debugbacktrace] = true }
	opt.on('--custom <hookfile>', 'loads the ruby script hookfile and invokes "dasm_setup(exe, dasm)"') { |h| opts[:hookfile] = h }
	opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
	opt.on('-v', '--verbose') { $VERBOSE = true }
	opt.on('-d', '--debug') { $DEBUG = true }
}.parse!(ARGV)

exename = ARGV.shift

if not exename
	w = Metasm::GtkGui::OpenFile.new(nil, 'chose target binary') { |t| exename = t }
	w.signal_connect('destroy') { Gtk.main_quit }
	Gtk.main
	exit if not exename
end

exe = Metasm::AutoExe.orshellcode.decode_file(exename)
dasm = exe.init_disassembler

dasm.parse_c_file opts[:cheader] if opts[:cheader]
dasm.backtrace_maxblocks_data = -1 if opts[:nodatatrace]
dasm.debug_backtrace = true if opts[:debugbacktrace]
if opts[:hookfile]
	load opts[:hookfile]
	dasm_setup(exe, dasm)
end


ep = ARGV.map { |arg| (?0..?9).include?(arg[0]) ? Integer(arg) : arg }

w = Metasm::GtkGui::MainWindow.new("#{exename} - metasm disassembler").display(dasm, ep)
w.dasm_widget.focus_addr ep.first if not ep.empty?
w.signal_connect('destroy') { Gtk.main_quit }
Gtk.main
