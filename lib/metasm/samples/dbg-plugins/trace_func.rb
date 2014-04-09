#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm debugger plugin
# adds a 'trace_func' method to the debugger
# the methods sets a breakpoint at the beginning of a function, and logs the execution of the instruction blocks
# does not descend in subfunctions

# setup the initial breakpoint at func start
def trace_func(addr, oneshot = false)
  @trace_terminate = false
  # distinguish different hits on the same function entry
  counter = 0
  bp = bpx(addr, oneshot) {
    counter += 1
    id = [disassembler.normalize(addr), counter, func_retaddr]
    trace_func_newtrace(id)
    trace_func_block(id)
    continue
  }
  if addr == pc
    del_bp bp if oneshot
    bp.action.call
  end
end

# start tracing now, and stop only when @trace_terminate is set
def trace
  @trace_subfuncs = true
  @trace_terminate = false
  id = [pc, 0, 0]
  trace_func_newtrace(id)
  trace_func_block(id)
  continue
end

# we hit the beginning of a block we want to trace
def trace_func_block(id)
  blockaddr = pc
  if b = trace_get_block(blockaddr)
    trace_func_add_block(id, blockaddr)
    if b.list.length == 1
      trace_func_blockend(id, blockaddr)
    else
      bpx(b.list.last.address, true) {
        finished = trace_func_blockend(id, blockaddr)
        continue if not finished
      }
    end
  else
    # invalid opcode ?
    trace_func_blockend(id, blockaddr)
  end
end

# we are at the end of a traced block, find whats next
def trace_func_blockend(id, blockaddr)
  if di = disassembler.di_at(pc)
    if end_stepout(di) and trace_func_istraceend(id, di)
      # trace ends there
      trace_func_finish(id)
      return true
    elsif di.opcode.props[:saveip] and not trace_func_entersubfunc(id, di)
      # call to a subfunction
      bpx(di.next_addr, true) {
        trace_func_block(id)
        continue
      }
      continue
    else
      singlestep {
        newaddr = pc
        trace_func_block(id)

        trace_func_linkdasm(di.address, newaddr)
        continue
      }
    end
  else
    # XXX should link in the dasm somehow
    singlestep {
      trace_func_block(id)
      continue
    }
  end
  false
end

# retrieve an instructionblock, disassemble if needed
def trace_get_block(addr)
  # TODO trace all blocks from addr for which we know the target, stop on call / jmp [foo]
  disassembler.disassemble_fast_block(addr)
  if di = disassembler.di_at(addr)
    di.block
  end
end

# update the blocks links in the disassembler
def trace_func_linkdasm(from_addr, new_addr)
  di = disassembler.di_at(from_addr)
  ndi = disassembler.di_at(new_addr)

  return if not di

  # is it a subfunction return ?
  if end_stepout(di) and cdi = (1..8).map { |i|
        disassembler.di_at(new_addr - i)
      }.compact.find { |cdi_|
        cdi_.opcode.props[:saveip] and cdi_.next_addr == new_addr
      }
    cdi.block.add_to_subfuncret new_addr
    ndi.block.add_from_subfuncret cdi.address if ndi
    cdi.block.each_to_normal { |f|
      disassembler.function[f] ||= DecodedFunction.new if disassembler.di_at(f)
    }
  else
    di.block.add_to_normal new_addr
    ndi.block.add_from_normal from_addr if ndi
  end
end

################################################################################################
# you can redefine the following functions in another plugin to handle trace events differently

# a new trace is about to begin
def trace_func_newtrace(id)
  @trace_func_counter ||= {}
  @trace_func_counter[id] = 0

  puts "start tracing #{Expression[id[0]]}"

  # setup a bg_color_callback on the disassembler
  if not defined? @trace_func_dasmcolor
    @trace_func_dasmcolor = true
    return if not disassembler.gui
    oldcb = disassembler.gui.bg_color_callback
    disassembler.gui.bg_color_callback = lambda { |addr|
      if oldcb and c = oldcb[addr]
        c
      elsif di = disassembler.di_at(addr) and di.block.list.first.comment.to_s =~ /functrace/
        'ff0'
      end
    }
  end
end

# a new block is added to a trace
def trace_func_add_block(id, blockaddr)
  @trace_func_counter[id] += 1
  if di = disassembler.di_at(blockaddr)
    di.add_comment "functrace #{@trace_func_counter[id]}"
  end
end

# the trace is finished
def trace_func_finish(id)
  puts "finished tracing #{Expression[id[0]]}"
end

def trace_subfuncs=(v) @trace_subfuncs = v end
def trace_subfuncs; @trace_subfuncs ||= false end

# the tracer is on a end-of-func instruction, should the trace end ?
def trace_func_istraceend(id, di)
  if trace_subfuncs
    if @trace_terminate
      true
    elsif id[2] == 0	# trace VS func_trace
    elsif target = disassembler.get_xrefs_x(di)[0]
      # check the current return address against the one saved at trace start
      resolve(disassembler.normalize(target)) == id[2]
    end
  else
    true
  end
end

# the tracer is on a subfunction call instruction, should it trace into or stepover ?
def trace_func_entersubfunc(id, di)
  if trace_subfuncs
    @trace_func_subfunccache ||= {}
    if not target = @trace_func_subfunccache[di.address]
      # even if the target is dynamic, its module should be static
      if target = disassembler.get_xrefs_x(di)[0]
        @trace_func_subfunccache[di.address] =
        target = resolve(disassembler.normalize(target))
      end
    end
    # check if the target subfunction is in the same module as the main
    # XXX should check against the list of loaded modules etc
    # XXX call thunk_foo -> jmp [other_module]
    true if target.kind_of? Integer and target & 0xffc0_0000 == id[0] & 0xffc0_0000
  else
    false
  end
end

if gui
  gui.new_command('trace_func', 'trace execution inside a target function') { |arg| trace_func arg }
  gui.new_command('trace_func_once', 'trace one execution inside the target function') { |arg| trace_func arg, true }
  gui.new_command('trace_now', 'trace til the end of the current function') { trace_func pc, true ; gui.wrap_run { continue } }
  gui.new_command('trace', 'start tracing from the current pc until trace_stop') { trace }
  gui.new_command('trace_stop', 'stop tracing') { @trace_terminate = true }
  gui.new_command('trace_subfunctions', 'define if the tracer should enter subfunctions') { |arg|
    case arg.strip
    when 'on', '1', 'yes', 'y'; @trace_subfuncs = true
    else @trace_subfuncs = false
    end
    puts "#{'not ' if not @trace_subfuncs}tracing subfunctions"
  }
end
