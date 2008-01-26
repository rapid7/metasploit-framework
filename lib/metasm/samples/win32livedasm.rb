#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

# open target
WinAPI.get_debug_privilege
if not pr = WinAPI.find_process((Integer(ARGV.first) rescue ARGV.first))
	puts WinAPI.list_processes.sort_by { |pr| pr.pid }.map { |pr| "#{pr.pid}: #{File.basename(pr.modules.first.path) rescue nil}" }
	exit
end
# virtual mapping of remote process memory
remote_mem = WindowsRemoteString.open_pid(pr.pid)

# retrieve the pe load address
baseaddr = pr.modules[0].addr

# decode the COFF headers
pe = Metasm::LoadedPE.load remote_mem[baseaddr, 0x100000]
pe.decode_header

# get the entrypoint address
eip = baseaddr + pe.optheader.entrypoint

# use degraded disasm mode: assume all calls will return
String.cpu.make_call_return	# String.cpu is the Ia32 cpu set up by metasm-shell

# disassemble & dump opcodes
puts pe.encoded[pe.optheader.entrypoint, 0x100].data.decode(eip)
