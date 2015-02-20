#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
Metasm.require 'samples/metasm-shell'

include Metasm

# open target
WinOS.get_debug_privilege
if not pr = WinOS.find_process(ARGV.first)
  puts WinOS.list_processes.sort_by { |pr_| pr_.pid }
  exit
end

# retrieve the pe load address
baseaddr = pr.modules[0].addr

# decode the COFF headers
pe = Metasm::LoadedPE.load pr.memory[baseaddr, 0x100000]
pe.decode_header

# get the entrypoint address
eip = baseaddr + pe.label_rva(pe.optheader.entrypoint)

# use degraded disasm mode: assume all calls will return
String.cpu.opcode_list.each { |op| op.props.delete :stopexec if op.props[:saveip] }

# disassemble & dump opcodes
puts pe.encoded[pe.optheader.entrypoint, 0x100].data.decode(eip)
