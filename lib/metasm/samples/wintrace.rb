#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this is a simple executable tracer for Windows using the
# Metasm windows debug api abstraction
# all callbacks are full ruby, so this is extremely slow !
#

require 'metasm'
Metasm.require 'samples/metasm-shell'

class Tracer < Metasm::WinDbgAPI
  def initialize(*a)
    super(*a)
    @label = {}
    @prog = Metasm::ExeFormat.new(Metasm::Ia32.new)
    loop
    puts 'finished'
  end

  def handler_newprocess(pid, tid, info)
    hide_debugger(pid, tid, info)
    Metasm::WinAPI::DBG_CONTINUE
  end

  def handler_newthread(pid, tid, info)
    do_singlestep(pid, tid)
    Metasm::WinAPI::DBG_CONTINUE
  end

  def handler_exception(pid, tid, info)
    do_singlestep(pid, tid) if @hthread[pid] and @hthread[pid][tid]
    case info.code
    when Metasm::WinAPI::STATUS_SINGLE_STEP
      Metasm::WinAPI::DBG_CONTINUE
    else super(pid, tid, info)
    end
  end

  def handler_loaddll(pid, tid, info)
    # update @label with exported symbols
    pe = Metasm::LoadedPE.load(@mem[pid][info.imagebase, 0x1000000])
    pe.decode_header
    pe.decode_exports
    libname = read_str_indirect(pid, info.imagename, info.unicode)
    if pe.export
      libname = pe.export.libname if libname == ''
      pe.export.exports.each { |e|
        next if not r = pe.label_rva(e.target)
        @label[info.imagebase + r] = libname + '!' + (e.name || "ord_#{e.ordinal}")
      }
    end
    super(pid, tid, info)
  end

  # dumps the opcode at eip, sets the trace flag
  def do_singlestep(pid, tid)
    ctx = get_context(pid, tid)
    eip = ctx[:eip]

    if l = @label[eip]
      puts l + ':'
    end
    if $VERBOSE
    bin = @mem[pid][eip, 16]
    di = @prog.cpu.decode_instruction(Metasm::EncodedData.new(bin), eip)
    puts "#{'%08X' % eip} #{di.instruction}"
    end

    ctx[:eflags] |= 0x100
  end

  # resets the DebuggerPresent field of the PEB
  def hide_debugger(pid, tid, info)
    peb = @mem[pid][info.threadlocalbase + 0x30, 4].unpack('L').first
    @mem[pid][peb + 2, 2] = [0].pack('S')
  end
end

if $0 == __FILE__
  Metasm::WinOS.get_debug_privilege
  if ARGV.empty?
    # display list of running processes if no target found
    puts Metasm::WinOS.list_processes.sort_by { |pr_| pr_.pid }
    abort 'target needed'
  end
  Tracer.new ARGV.shift.dup
end
