#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this file compliments disassemble.rb, adding misc user-friendly methods

module Metasm
class InstructionBlock
  # adds an address to the from_normal/from_subfuncret list
  def add_from(addr, type=:normal)
    send "add_from_#{type}", addr
  end
  def add_from_normal(addr)
    @from_normal ||= []
    @from_normal |= [addr]
  end
  def add_from_subfuncret(addr)
    @from_subfuncret ||= []
    @from_subfuncret |= [addr]
  end
  def add_from_indirect(addr)
    @from_indirect ||= []
    @from_indirect |= [addr]
  end
  # iterates over every from address, yields [address, type in [:normal, :subfuncret, :indirect]]
  def each_from
    each_from_normal { |a| yield a, :normal }
    each_from_subfuncret { |a| yield a, :subfuncret }
    each_from_indirect { |a| yield a, :indirect }
  end
  def each_from_normal(&b)
    @from_normal.each(&b) if from_normal
  end
  def each_from_subfuncret(&b)
    @from_subfuncret.each(&b) if from_subfuncret
  end
  def each_from_indirect(&b)
    @from_indirect.each(&b) if from_indirect
  end

  def add_to(addr, type=:normal)
    send "add_to_#{type}", addr
  end
  def add_to_normal(addr)
    @to_normal ||= []
    @to_normal |= [addr]
  end
  def add_to_subfuncret(addr)
    @to_subfuncret ||= []
    @to_subfuncret |= [addr]
  end
  def add_to_indirect(addr)
    @to_indirect ||= []
    @to_indirect |= [addr]
  end
  def each_to
    each_to_normal     { |a| yield a, :normal }
    each_to_subfuncret { |a| yield a, :subfuncret }
    each_to_indirect   { |a| yield a, :indirect }
  end
  def each_to_normal(&b)
    @to_normal.each(&b) if to_normal
  end
  def each_to_subfuncret(&b)
    @to_subfuncret.each(&b) if to_subfuncret
  end
  def each_to_indirect(&b)
    @to_indirect.each(&b) if to_indirect
  end

  # yields all from that are from the same function
  def each_from_samefunc(dasm, &b)
    return if dasm.function[address]
    @from_subfuncret.each(&b) if from_subfuncret
    @from_normal.each(&b) if from_normal
  end

  # yields all from that are not in the same subfunction as this block
  def each_from_otherfunc(dasm, &b)
    @from_normal.each(&b) if from_normal and dasm.function[address]
    @from_subfuncret.each(&b) if from_subfuncret and dasm.function[address]
    @from_indirect.each(&b) if from_indirect
  end

  # yields all to that are in the same subfunction as this block
  def each_to_samefunc(dasm)
    each_to { |to, type|
      next if type != :normal and type != :subfuncret
      to = dasm.normalize(to)
      yield to if not dasm.function[to]
    }
  end

  # yields all to that are not in the same subfunction as this block
  def each_to_otherfunc(dasm)
    each_to { |to, type|
      to = dasm.normalize(to)
      yield to if type == :indirect or dasm.function[to] or not dasm.decoded[to]
    }
  end

  # returns the array used in each_from_samefunc
  def from_samefunc(dasm)
    ary = []
    each_from_samefunc(dasm) { |a| ary << a }
    ary
  end
  def from_otherfunc(dasm)
    ary = []
    each_from_otherfunc(dasm) { |a| ary << a }
    ary
  end
  def to_samefunc(dasm)
    ary = []
    each_to_samefunc(dasm) { |a| ary << a }
    ary
  end
  def to_otherfunc(dasm)
    ary = []
    each_to_otherfunc(dasm) { |a| ary << a }
    ary
  end
end

class DecodedInstruction
  # checks if this instruction is the first of its IBlock
  def block_head?
    self == @block.list.first
  end
end

class CPU
  # compat alias, for scripts using older version of metasm
  def get_backtrace_binding(di) backtrace_binding(di) end
end

class Disassembler
  # access the default value for @@backtrace_maxblocks for newly created Disassemblers
  def self.backtrace_maxblocks ; @@backtrace_maxblocks ; end
  def self.backtrace_maxblocks=(b) ; @@backtrace_maxblocks = b ; end

  # adds a commentary at the given address
  # comments are found in the array @comment: {addr => [list of strings]}
  def add_comment(addr, cmt)
    @comment[addr] ||= []
    @comment[addr] |= [cmt]
  end

  # returns the 1st element of #get_section_at (ie the edata at a given address) or nil
  def get_edata_at(*a)
    if s = get_section_at(*a)
      s[0]
    end
  end

  # returns the DecodedInstruction at addr if it exists
  def di_at(addr)
    di = @decoded[addr] || @decoded[normalize(addr)] if addr
    di if di.kind_of? DecodedInstruction
  end

  # returns the InstructionBlock containing the address at addr
  def block_at(addr)
    di = di_at(addr)
    di.block if di
  end

  # returns the DecodedFunction at addr if it exists
  def function_at(addr)
    f = @function[addr] || @function[normalize(addr)] if addr
    f if f.kind_of? DecodedFunction
  end

  # returns the DecodedInstruction covering addr
  # returns one at starting nearest addr if multiple are available (overlapping instrs)
  def di_including(addr)
    return if not addr
    addr = normalize(addr)
    if off = (0...16).find { |o| @decoded[addr-o].kind_of? DecodedInstruction and @decoded[addr-o].bin_length > o }
      @decoded[addr-off]
    end
  end

  # returns the InstructionBlock containing the byte at addr
  # returns the one of di_including() on multiple matches (overlapping instrs)
  def block_including(addr)
    di = di_including(addr)
    di.block if di
  end

  # returns the DecodedFunction including this byte
  # return the one of find_function_start() if multiple are possible (block shared by multiple funcs)
  def function_including(addr)
    return if not di = di_including(addr)
    function_at(find_function_start(di.address))
  end

  # yields every InstructionBlock
  # returns the list of IBlocks
  def each_instructionblock(&b)
    ret = []
    @decoded.each { |addr, di|
      next if not di.kind_of? DecodedInstruction or not di.block_head?
      ret << di.block
      b.call(di.block) if b
    }
    ret
  end
  alias instructionblocks each_instructionblock

  # return a backtrace_binding reversed (akin to code emulation) (but not really)
  def get_fwdemu_binding(di, pc=nil)
    @cpu.get_fwdemu_binding(di, pc)
  end

  # reads len raw bytes from the mmaped address space
  def read_raw_data(addr, len)
    if e = get_section_at(addr)
      e[0].read(len)
    end
  end

  # read an int of arbitrary type (:u8, :i32, ...)
  def decode_int(addr, type)
    type = "u#{type*8}".to_sym if type.kind_of? Integer
    if e = get_section_at(addr)
      e[0].decode_imm(type, @cpu.endianness)
    end
  end

  # read a byte at address addr
  def decode_byte(addr)
    decode_int(addr, :u8)
  end

  # read a dword at address addr
  # the dword is cpu-sized (eg 32 or 64bits)
  def decode_dword(addr)
    decode_int(addr, @cpu.size/8)
  end

  # read a zero-terminated string from addr
  # if no terminal 0 is found, return nil
  def decode_strz(addr, maxsz=4096)
    if e = get_section_at(addr)
      str = e[0].read(maxsz).to_s
      return if not len = str.index(?\0)
      str[0, len]
    end
  end

  # read a zero-terminated wide string from addr
  # return nil if no terminal found
  def decode_wstrz(addr, maxsz=4096)
    if e = get_section_at(addr)
      str = e[0].read(maxsz).to_s
      return if not len = str.unpack('v*').index(0)
      str[0, 2*len]
    end
  end

  # disassembles one instruction at address
  # returns nil if no instruction can be decoded there
  # does not update any internal state of the disassembler, nor reuse the @decoded cache
  def disassemble_instruction(addr)
    if e = get_section_at(addr)
      @cpu.decode_instruction(e[0], normalize(addr))
    end
  end

  # disassemble addr as if the code flow came from from_addr
  def disassemble_from(addr, from_addr)
    from_addr = from_addr.address if from_addr.kind_of? DecodedInstruction
    from_addr = normalize(from_addr)
    if b = block_at(from_addr)
      b.add_to_normal(addr)
    end
    @addrs_todo << [addr, from_addr]
    disassemble
  end

  # returns the label associated to an addr, or nil if none exist
  def get_label_at(addr)
    e = get_edata_at(addr, false)
    e.inv_export[e.ptr] if e
  end

  # sets the label for the specified address
  # returns nil if the address is not mapped
  # memcheck is passed to get_section_at to validate that the address is mapped
  # keep existing label if 'overwrite' is false
  def set_label_at(addr, name, memcheck=true, overwrite=true)
    addr = Expression[addr].reduce
    e, b = get_section_at(addr, memcheck)
    if not e
    elsif not l = e.inv_export[e.ptr] or (!overwrite and l != name)
      l = @program.new_label(name)
      e.add_export l, e.ptr
      @label_alias_cache = nil
      @old_prog_binding[l] = @prog_binding[l] = b + e.ptr
    elsif l != name
      l = rename_label l, @program.new_label(name)
    end
    l
  end

  # remove a label at address addr
  def del_label_at(addr, name=get_label_at(addr))
    ed = get_edata_at(addr)
    if ed and ed.inv_export[ed.ptr]
      ed.del_export name, ed.ptr
      @label_alias_cache = nil
    end
    each_xref(addr) { |xr|
      next if not xr.origin or not o = @decoded[xr.origin] or not o.kind_of? Renderable
      o.each_expr { |e|
        next unless e.kind_of?(Expression)
        e.lexpr = addr if e.lexpr == name
        e.rexpr = addr if e.rexpr == name
      }
    }
    @old_prog_binding.delete name
    @prog_binding.delete name
  end

  # changes a label to another, updates referring instructions etc
  # returns the new label
  # the new label must be program-uniq (see @program.new_label)
  def rename_label(old, new)
    return new if old == new
    raise "label #{new.inspect} exists" if @prog_binding[new]
    each_xref(normalize(old)) { |x|
      next if not di = @decoded[x.origin]
      @cpu.replace_instr_arg_immediate(di.instruction, old, new)
      di.comment.to_a.each { |c| c.gsub!(old, new) }
    }
    e = get_edata_at(old, false)
    if e
      e.add_export new, e.export.delete(old), true
    end
    raise "cant rename nonexisting label #{old}" if not @prog_binding[old]
    @label_alias_cache = nil
    @old_prog_binding[new] = @prog_binding[new] = @prog_binding.delete(old)
    @addrs_todo.each { |at|
      case at[0]
      when old; at[0] = new
      when Expression; at[0] = at[0].bind(old => new)
      end
    }

    if @inv_section_reloc[old]
      @inv_section_reloc[old].each { |b, e_, o, r|
        (0..16).each { |off|
          if di = @decoded[Expression[b]+o-off] and di.bin_length > off
            @cpu.replace_instr_arg_immediate(di.instruction, old, new)
          end
        }
        r.target = r.target.bind(old => new)
      }
      @inv_section_reloc[new] = @inv_section_reloc.delete(old)
    end

    if c_parser and @c_parser.toplevel.symbol[old]
      @c_parser.toplevel.symbol[new] = @c_parser.toplevel.symbol.delete(old)
      @c_parser.toplevel.symbol[new].name = new
    end

    new
  end

  # finds the start of a function from the address of an instruction
  def find_function_start(addr)
    addr = addr.address if addr.kind_of? DecodedInstruction
    todo = [addr]
    done = []
    while a = todo.pop
      a = normalize(a)
      di = @decoded[a]
      next if done.include? a or not di.kind_of? DecodedInstruction
      done << a
      a = di.block.address
      break a if @function[a]
      l = []
      di.block.each_from_samefunc(self) { |f| l << f }
      break a if l.empty?
      todo.concat l
    end
  end

  # iterates over the blocks of a function, yields each func block address
  # returns the graph of blocks (block address => [list of samefunc blocks])
  def each_function_block(addr, incl_subfuncs = false, find_func_start = true)
    addr = @function.index(addr) if addr.kind_of? DecodedFunction
    addr = addr.address if addr.kind_of? DecodedInstruction
    addr = find_function_start(addr) if not @function[addr] and find_func_start
    todo = [addr]
    ret = {}
    while a = todo.pop
      next if not di = di_at(a)
      a = di.block.address
      next if ret[a]
      ret[a] = []
      yield a if block_given?
      di.block.each_to_samefunc(self) { |f| ret[a] << f ; todo << f }
      di.block.each_to_otherfunc(self) { |f| ret[a] << f ; todo << f } if incl_subfuncs
    end
    ret
  end
  alias function_blocks each_function_block

  # returns a graph of function calls
  # for each func passed as arg (default: all), update the 'ret' hash
  # associating func => [list of direct subfuncs called]
  def function_graph(funcs = @function.keys + @entrypoints.to_a, ret={})
    funcs = funcs.map { |f| normalize(f) }.uniq.find_all { |f| @decoded[f] }
    funcs.each { |f|
      next if ret[f]
      ret[f] = []
      each_function_block(f) { |b|
        @decoded[b].block.each_to_otherfunc(self) { |sf|
          ret[f] |= [sf]
        }
      }
    }
    ret
  end

  # return the graph of function => subfunction list
  # recurses from an entrypoint
  def function_graph_from(addr)
    addr = normalize(addr)
    addr = find_function_start(addr) || addr
    ret = {}
    osz = ret.length-1
    while ret.length != osz
      osz = ret.length
      function_graph(ret.values.flatten + [addr], ret)
    end
    ret
  end

  # return the graph of function => subfunction list
  # for which a (sub-sub)function includes addr
  def function_graph_to(addr)
    addr = normalize(addr)
    addr = find_function_start(addr) || addr
    full = function_graph
    ret = {}
    todo = [addr]
    done = []
    while a = todo.pop
      next if done.include? a
      done << a
      full.each { |f, sf|
        next if not sf.include? a
        ret[f] ||= []
        ret[f] |= [a]
        todo << f
      }
    end
    ret
  end

  # returns info on sections, from @program if supported
  # returns an array of [name, addr, length, info]
  def section_info
    if @program.respond_to? :section_info
      @program.section_info
    else
      list = []
      @sections.each { |k, v|
        list << [get_label_at(k), normalize(k), v.length, nil]
      }
      list
    end
  end

  # transform an address into a file offset
  def addr_to_fileoff(addr)
    addr = normalize(addr)
    @program.addr_to_fileoff(addr)
  end

  # transform a file offset into an address
  def fileoff_to_addr(foff)
    @program.fileoff_to_addr(foff)
  end

  # remove the decodedinstruction from..to, replace them by the new Instructions in 'by'
  # this updates the block list structure, old di will still be visible in @decoded, except from original block (those are deleted)
  # if from..to spans multiple blocks
  #  to.block is splitted after to
  #  all path from from are replaced by a single link to after 'to', be careful !
  #   (eg a->b->... & a->c ; from in a, to in c => a->b is lost)
  #  all instructions are stuffed in the first block
  #  paths are only walked using from/to_normal
  # 'by' may be empty
  # returns the block containing the new instrs (nil if empty)
  def replace_instrs(from, to, by, patch_by=false)
    raise 'bad from' if not fdi = di_at(from) or not fdi.block.list.index(fdi)
    raise 'bad to' if not tdi = di_at(to) or not tdi.block.list.index(tdi)

    # create DecodedInstruction from Instructions in 'by' if needed
    split_block(fdi.block, fdi.address)
    split_block(tdi.block, tdi.block.list[tdi.block.list.index(tdi)+1].address) if tdi != tdi.block.list.last
    fb = fdi.block
    tb = tdi.block

    # generate DecodedInstr from Instrs
    # try to keep the bin_length of original block
    wantlen = tdi.address + tdi.bin_length - fb.address
    wantlen -= by.grep(DecodedInstruction).inject(0) { |len, di| len + di.bin_length }
    ldi = by.last
    ldi = DecodedInstruction.new(ldi) if ldi.kind_of? Instruction
    nb_i = by.grep(Instruction).length
    wantlen = nb_i if wantlen < 0 or (ldi and ldi.opcode.props[:setip])
    if patch_by
      by.map! { |di|
        if di.kind_of? Instruction
          di = DecodedInstruction.new(di)
          wantlen -= di.bin_length = wantlen / by.grep(Instruction).length
          nb_i -= 1
        end
        di
      }
    else
      by = by.map { |di|
        if di.kind_of? Instruction
          di = DecodedInstruction.new(di)
          wantlen -= (di.bin_length = wantlen / nb_i)
          nb_i -= 1
        end
        di
      }
    end


#puts "  ** patch next_addr to #{Expression[tb.list.last.next_addr]}" if not by.empty? and by.last.opcode.props[:saveip]
    by.last.next_addr = tb.list.last.next_addr if not by.empty? and by.last.opcode.props[:saveip]
    fb.list.each { |di| @decoded.delete di.address }
    fb.list.clear
    tb.list.each { |di| @decoded.delete di.address }
    tb.list.clear
    by.each { |di| fb.add_di di }
    by.each_with_index { |di, i|
      if odi = di_at(di.address)
        # collision, hopefully with another deobfuscation run ?
        if by[i..-1].all? { |mydi| mydi.to_s == @decoded[mydi.address].to_s }
          puts "replace_instrs: merge at  #{di}" if $DEBUG
          by[i..-1] = by[i..-1].map { |xdi| @decoded[xdi.address] }
          by[i..-1].each { fb.list.pop }
          split_block(odi.block, odi.address)
          tb.to_normal = [di.address]
          (odi.block.from_normal ||= []) << to
          odi.block.from_normal.uniq!
          break
        else
          #raise "replace_instrs: collision  #{di}  vs  #{odi}"
          puts "replace_instrs: collision  #{di}  vs  #{odi}" if $VERBOSE
          while @decoded[di.address].kind_of? DecodedInstruction	# find free space.. raise ?
            di.address += 1	# XXX use floats ?
            di.bin_length -= 1
          end
        end
      end
      @decoded[di.address] = di
    }
    @addrs_done.delete_if { |ad| normalize(ad[0]) == tb.address or ad[1] == tb.address }
    @addrs_done.delete_if { |ad| normalize(ad[0]) == fb.address or ad[1] == fb.address } if by.empty? and tb.address != fb.address

    # update to_normal/from_normal
    fb.to_normal = tb.to_normal
    fb.to_normal.to_a.each { |newto|
      # other paths may already point to newto, we must only update the relevant entry
      if ndi = di_at(newto) and idx = ndi.block.from_normal.to_a.index(to)
        if by.empty?
          ndi.block.from_normal[idx,1] = fb.from_normal.to_a
        else
          ndi.block.from_normal[idx] = fb.list.last.address
        end
      end
    }

    fb.to_subfuncret = tb.to_subfuncret
    fb.to_subfuncret.to_a.each { |newto|
      if ndi = di_at(newto) and idx = ndi.block.from_subfuncret.to_a.index(to)
        if by.empty?
          ndi.block.from_subfuncret[idx,1] = fb.from_subfuncret.to_a
        else
          ndi.block.from_subfuncret[idx] = fb.list.last.address
        end
      end
    }

    if by.empty?
      tb.to_subfuncret = nil if tb.to_subfuncret == []
      tolist = tb.to_subfuncret || tb.to_normal.to_a
      if lfrom = get_label_at(fb.address) and tolist.length == 1
        lto = auto_label_at(tolist.first)
        each_xref(fb.address, :x) { |x|
          next if not di = @decoded[x.origin]
          @cpu.replace_instr_arg_immediate(di.instruction, lfrom, lto)
          di.comment.to_a.each { |c| c.gsub!(lfrom, lto) }
        }
      end
      fb.from_normal.to_a.each { |newfrom|
        if ndi = di_at(newfrom) and idx = ndi.block.to_normal.to_a.index(from)
          ndi.block.to_normal[idx..idx] = tolist
        end
      }
      fb.from_subfuncret.to_a.each { |newfrom|
        if ndi = di_at(newfrom) and idx = ndi.block.to_subfuncret.to_a.index(from)
          ndi.block.to_subfuncret[idx..idx] = tolist
        end
      }
    else
      # merge with adjacent blocks
      merge_blocks(fb, fb.to_normal.first) if fb.to_normal.to_a.length == 1 and di_at(fb.to_normal.first)
      merge_blocks(fb.from_normal.first, fb) if fb.from_normal.to_a.length == 1 and di_at(fb.from_normal.first)
    end

    fb if not by.empty?
  end

  # undefine a sequence of decodedinstructions from an address
  # stops at first non-linear branch
  # removes @decoded, @comments, @xrefs, @addrs_done
  # does not update @prog_binding (does not undefine labels)
  def undefine_from(addr)
    return if not di_at(addr)
    @comment.delete addr if @function.delete addr
    split_block(addr)
    addrs = []
    while di = di_at(addr)
      di.block.list.each { |ddi| addrs << ddi.address }
      break if di.block.to_subfuncret.to_a != [] or di.block.to_normal.to_a.length != 1
      addr = di.block.to_normal.first
      break if ndi = di_at(addr) and ndi.block.from_normal.to_a.length != 1
    end
    addrs.each { |a| @decoded.delete a }
    @xrefs.delete_if { |a, x|
      if not x.kind_of? Array
        true if x and addrs.include? x.origin
      else
        x.delete_if { |xx| addrs.include? xx.origin }
        true if x.empty?
      end
    }
    @addrs_done.delete_if { |ad| !(addrs & [normalize(ad[0]), normalize(ad[1])]).empty? }
  end

  # merge two instruction blocks if they form a simple chain and are adjacent
  # returns true if merged
  def merge_blocks(b1, b2, allow_nonadjacent = false)
    if b1 and not b1.kind_of? InstructionBlock
      return if not b1 = block_at(b1)
    end
    if b2 and not b2.kind_of? InstructionBlock
      return if not b2 = block_at(b2)
    end
    if b1 and b2 and (allow_nonadjacent or b1.list.last.next_addr == b2.address) and
        b1.to_normal.to_a == [b2.address] and b2.from_normal.to_a.length == 1 and	# that handles delay_slot
        b1.to_subfuncret.to_a == [] and b2.from_subfuncret.to_a == [] and
        b1.to_indirect.to_a == [] and b2.from_indirect.to_a == []
      b2.list.each { |di| b1.add_di di }
      b1.to_normal = b2.to_normal
      b2.list.clear
      @addrs_done.delete_if { |ad| normalize(ad[0]) == b2.address }
      true
    end
  end

  # computes the binding of a code sequence
  # just a forwarder to CPU#code_binding
  def code_binding(*a)
    @cpu.code_binding(self, *a)
  end

  # returns an array of instructions/label that, once parsed and assembled, should
  # give something equivalent to the code accessible from the (list of) entrypoints given
  # from the @decoded dasm graph
  # assume all jump targets have a matching label in @prog_binding
  # may add inconditionnal jumps in the listing to preserve the code flow
  def flatten_graph(entry, include_subfunc=true)
    ret = []
    entry = [entry] if not entry.kind_of? Array
    todo = entry.map { |a| normalize(a) }
    done = []
    inv_binding = @prog_binding.invert
    while addr = todo.pop
      next if done.include? addr or not di_at(addr)
      done << addr
      b = @decoded[addr].block

      ret << Label.new(inv_binding[addr]) if inv_binding[addr]
      ret.concat b.list.map { |di| di.instruction }

      b.each_to_otherfunc(self) { |to|
        to = normalize to
        todo.unshift to if include_subfunc
      }
      b.each_to_samefunc(self) { |to|
        to = normalize to
        todo << to
      }

      if not di = b.list[-1-@cpu.delay_slot] or not di.opcode.props[:stopexec] or di.opcode.props[:saveip]
        to = b.list.last.next_addr
        if todo.include? to
          if done.include? to or not di_at(to)
            if not to_l = inv_binding[to]
              to_l = auto_label_at(to, 'loc')
              if done.include? to and idx = ret.index(@decoded[to].block.list.first.instruction)
                ret.insert(idx, Label.new(to_l))
              end
            end
            ret << @cpu.instr_uncond_jump_to(to_l)
          else
            todo << to	# ensure it's next in the listing
          end
        end
      end
    end

    ret
  end

  # returns a demangled C++ name
  def demangle_cppname(name)
    case name[0]
    when ??	# MSVC
      name = name[1..-1]
      demangle_msvc(name[1..-1]) if name[0] == ??
    when ?_
      name = name.sub(/_GLOBAL__[ID]_/, '')
      demangle_gcc(name[2..-1][/\S*/]) if name[0, 2] == '_Z'
    end
  end

  # from wgcc-2.2.2/undecorate.cpp
  # TODO
  def demangle_msvc(name)
    op = name[0, 1]
    op = name[0, 2] if op == '_'
    if op = {
  '2' => "new", '3' => "delete", '4' => "=", '5' => ">>", '6' => "<<", '7' => "!", '8' => "==", '9' => "!=",
  'A' => "[]", 'C' => "->", 'D' => "*", 'E' => "++", 'F' => "--", 'G' => "-", 'H' => "+", 'I' => "&",
  'J' => "->*", 'K' => "/", 'L' => "%", 'M' => "<", 'N' => "<=", 'O' => ">", 'P' => ">=", 'Q' => ",",
  'R' => "()", 'S' => "~", 'T' => "^", 'U' => "|", 'V' => "&&", 'W' => "||", 'X' => "*=", 'Y' => "+=",
  'Z' => "-=", '_0' => "/=", '_1' => "%=", '_2' => ">>=", '_3' => "<<=", '_4' => "&=", '_5' => "|=", '_6' => "^=",
  '_7' => "`vftable'", '_8' => "`vbtable'", '_9' => "`vcall'", '_A' => "`typeof'", '_B' => "`local static guard'",
  '_C' => "`string'", '_D' => "`vbase destructor'", '_E' => "`vector deleting destructor'", '_F' => "`default constructor closure'",
  '_G' => "`scalar deleting destructor'", '_H' => "`vector constructor iterator'", '_I' => "`vector destructor iterator'",
  '_J' => "`vector vbase constructor iterator'", '_K' => "`virtual displacement map'", '_L' => "`eh vector constructor iterator'",
  '_M' => "`eh vector destructor iterator'", '_N' => "`eh vector vbase constructor iterator'", '_O' => "`copy constructor closure'",
  '_S' => "`local vftable'", '_T' => "`local vftable constructor closure'", '_U' => "new[]", '_V' => "delete[]",
  '_X' => "`placement delete closure'", '_Y' => "`placement delete[] closure'"}[op]
      op[0] == ?` ? op[1..-2] : "op_#{op}"
    end
  end

  # from http://www.codesourcery.com/public/cxx-abi/abi.html
  def demangle_gcc(name)
    subs = []
    ret = ''
    decode_tok = lambda {
      name ||= ''
      case name[0]
      when nil
        ret = nil
      when ?N
        name = name[1..-1]
        decode_tok[]
        until name[0] == ?E
          break if not ret
          ret << '::'
          decode_tok[]
        end
        name = name[1..-1]
      when ?I
        name = name[1..-1]
        ret = ret[0..-3] if ret[-2, 2] == '::'
        ret << '<'
        decode_tok[]
        until name[0] == ?E
          break if not ret
          ret << ', '
          decode_tok[]
        end
        ret << ' ' if ret and ret[-1] == ?>
        ret << '>' if ret
        name = name[1..-1]
      when ?T
        case name[1]
        when ?T; ret << 'vtti('
        when ?V; ret << 'vtable('
        when ?I; ret << 'typeinfo('
        when ?S; ret << 'typename('
        else ret = nil
        end
        name = name[2..-1].to_s
        decode_tok[] if ret
        ret << ')' if ret
        name = name[1..-1] if name[0] == ?E
      when ?C
        name = name[2..-1]
        base = ret[/([^:]*)(<.*|::)?$/, 1]
        ret << base
      when ?D
        name = name[2..-1]
        base = ret[/([^:]*)(<.*|::)?$/, 1]
        ret << '~' << base
      when ?0..?9
        nr = name[/^[0-9]+/]
        name = name[nr.length..-1].to_s
        ret << name[0, nr.to_i]
        name = name[nr.to_i..-1]
        subs << ret[/[\w:]*$/]
      when ?S
        name = name[1..-1]
        case name[0]
        when ?_, ?0..?9, ?A..?Z
          case name[0]
          when ?_; idx = 0 ; name = name[1..-1]
          when ?0..?9; idx = name[0, 1].unpack('C')[0] - 0x30 + 1 ; name = name[2..-1]
          when ?A..?Z; idx = name[0, 1].unpack('C')[0] - 0x41 + 11 ; name = name[2..-1]
          end
          if not subs[idx]
            ret = nil
          else
            ret << subs[idx]
          end
        when ?t
          ret << 'std::'
          name = name[1..-1]
          decode_tok[]
        else
          std = { ?a => 'std::allocator',
            ?b => 'std::basic_string',
            ?s => 'std::string', # 'std::basic_string < char, std::char_traits<char>, std::allocator<char> >',
            ?i => 'std::istream', # 'std::basic_istream<char,  std::char_traits<char> >',
            ?o => 'std::ostream', # 'std::basic_ostream<char,  std::char_traits<char> >',
            ?d => 'std::iostream', # 'std::basic_iostream<char, std::char_traits<char> >'
          }[name[0]]
          if not std
            ret = nil
          else
            ret << std
          end
          name = name[1..-1]
        end
      when ?P, ?R, ?r, ?V, ?K
        attr = { ?P => '*', ?R => '&', ?r => ' restrict', ?V => ' volatile', ?K => ' const' }[name[0]]
        name = name[1..-1]
        rl = ret.length
        decode_tok[]
        if ret
          ret << attr
          subs << ret[rl..-1]
        end
      else
        if ret =~ /[(<]/ and ty = {
      ?v => 'void', ?w => 'wchar_t', ?b => 'bool', ?c => 'char', ?a => 'signed char',
      ?h => 'unsigned char', ?s => 'short', ?t => 'unsigned short', ?i => 'int',
      ?j => 'unsigned int', ?l => 'long', ?m => 'unsigned long', ?x => '__int64',
      ?y => 'unsigned __int64', ?n => '__int128', ?o => 'unsigned __int128', ?f => 'float',
      ?d => 'double', ?e => 'long double', ?g => '__float128', ?z => '...'
        }[name[0]]
          name = name[1..-1]
          ret << ty
        else
          fu = name[0, 2]
          name = name[2..-1]
          if op = {
      'nw' => ' new', 'na' => ' new[]', 'dl' => ' delete', 'da' => ' delete[]',
      'ps' => '+', 'ng' => '-', 'ad' => '&', 'de' => '*', 'co' => '~', 'pl' => '+',
      'mi' => '-', 'ml' => '*', 'dv' => '/', 'rm' => '%', 'an' => '&', 'or' => '|',
      'eo' => '^', 'aS' => '=', 'pL' => '+=', 'mI' => '-=', 'mL' => '*=', 'dV' => '/=',
      'rM' => '%=', 'aN' => '&=', 'oR' => '|=', 'eO' => '^=', 'ls' => '<<', 'rs' => '>>',
      'lS' => '<<=', 'rS' => '>>=', 'eq' => '==', 'ne' => '!=', 'lt' => '<', 'gt' => '>',
      'le' => '<=', 'ge' => '>=', 'nt' => '!', 'aa' => '&&', 'oo' => '||', 'pp' => '++',
      'mm' => '--', 'cm' => ',', 'pm' => '->*', 'pt' => '->', 'cl' => '()', 'ix' => '[]',
      'qu' => '?', 'st' => ' sizeof', 'sz' => ' sizeof', 'at' => ' alignof', 'az' => ' alignof'
          }[fu]
            ret << "operator#{op}"
          elsif fu == 'cv'
            ret << "cast<"
            decode_tok[]
            ret << ">" if ret
          else
            ret = nil
          end
        end
      end
      name ||= ''
    }

    decode_tok[]
    subs.pop
    if ret and name != ''
      ret << '('
      decode_tok[]
      while ret and name != ''
        ret << ', '
        decode_tok[]
      end
      ret << ')' if ret
    end
    ret
  end

  # scans all the sections raw for a given regexp
  # return/yields all the addresses matching
  # if yield returns nil/false, do not include the addr in the final result
  # sections are scanned MB by MB, so this should work (slowly) on 4GB sections (eg debugger VM)
  # with addr_start/length, symbol-based section are skipped
  def pattern_scan(pat, addr_start=nil, length=nil, chunksz=nil, margin=nil, &b)
    chunksz ||= 4*1024*1024	# scan 4MB at a time
    margin ||= 65536	# add this much bytes at each chunk to find /pat/ over chunk boundaries

    pat = Regexp.new(Regexp.escape(pat)) if pat.kind_of? ::String

    found = []
    @sections.each { |sec_addr, e|
      if addr_start
        length ||= 0x1000_0000
        begin
          if sec_addr < addr_start
            next if sec_addr+e.length <= addr_start
            e = e[addr_start-sec_addr, e.length]
            sec_addr = addr_start
          end
          if sec_addr+e.length > addr_start+length
            next if sec_addr > addr_start+length
            e = e[0, sec_addr+e.length-(addr_start+length)]
          end
        rescue
          puts $!, $!.message, $!.backtrace if $DEBUG
          # catch arithmetic error with symbol-based section
          next
        end
      end
      e.pattern_scan(pat, chunksz, margin) { |eo|
        match_addr = sec_addr + eo
        found << match_addr if not b or b.call(match_addr)
        false
      }
    }
    found
  end

  # returns/yields [addr, string] found using pattern_scan /[\x20-\x7e]/
  def strings_scan(minlen=6, &b)
    ret = []
    nexto = 0
    pattern_scan(/[\x20-\x7e]{#{minlen},}/m, nil, 1024) { |o|
      if o - nexto > 0
        next unless e = get_edata_at(o)
        str = e.data[e.ptr, 1024][/[\x20-\x7e]{#{minlen},}/m]
        ret << [o, str] if not b or b.call(o, str)
        nexto = o + str.length
      end
    }
    ret
  end

  # exports the addr => symbol map (see load_map)
  def save_map
    @prog_binding.map { |l, o|
      type = di_at(o) ? 'c' : 'd'	# XXX
      o = o.to_s(16).rjust(8, '0') if o.kind_of? ::Integer
      "#{o} #{type} #{l}"
    }
  end

  # loads a map file (addr => symbol)
  # off is an optionnal offset to add to every address found (for eg rebased binaries)
  # understands:
  #  standard map files (eg linux-kernel.map: <addr> <type> <name>, e.g. 'c01001ba t setup_idt')
  #  ida map files (<sectionidx>:<sectionoffset> <name>)
  # arg is either the map itself or the filename of the map (if it contains no newline)
  def load_map(str, off=0)
    str = File.read(str) rescue nil if not str.index("\n")
    sks = @sections.keys.sort
    seen = {}
    str.each_line { |l|
      case l.strip
      when /^([0-9A-F]+)\s+(\w+)\s+(\w+)/i	# kernel.map style
        addr = $1.to_i(16)+off
        set_label_at(addr, $3, false, !seen[addr])
        seen[addr] = true
      when /^([0-9A-F]+):([0-9A-F]+)\s+([a-z_]\w+)/i	# IDA style
        # we do not have section load order, let's just hope that the addresses are sorted (and sortable..)
        #  could check the 1st part of the file, with section sizes, but it is not very convenient
        # the regexp is so that we skip the 1st part with section descriptions
        # in the file, section 1 is the 1st section ; we have an additionnal section (exe header) which fixes the 0-index
        addr = sks[$1.to_i(16)] + $2.to_i(16) + off
        set_label_at(addr, $3, false, !seen[addr])
        seen[addr] = true
      end
    }
  end

  # saves the dasm state in a file
  def save_file(file)
    tmpfile = file + '.tmp'
    File.open(tmpfile, 'wb') { |fd| save_io(fd) }
    File.rename tmpfile, file
  end

  # saves the dasm state to an IO
  def save_io(fd)
    fd.puts 'Metasm.dasm'

    if @program.filename and not @program.kind_of?(Shellcode)
      t = @program.filename.to_s
      fd.puts "binarypath #{t.length}", t
    else
      t = "#{@cpu.class.name.sub(/.*::/, '')} #{@cpu.size} #{@cpu.endianness}"
      fd.puts "cpu #{t.length}", t
      # XXX will be reloaded as a Shellcode with this CPU, but it may be a custom EXE
      # do not output binarypath, we'll be loaded as a Shellcode, 'section' will suffice
    end

    @sections.each { |a, e|
      # forget edata exports/relocs
      # dump at most 16Mo per section
      t = "#{Expression[a]} #{e.length}\n" +
        [e.data[0, 2**24].to_str].pack('m*')
      fd.puts "section #{t.length}", t
    }

    t = save_map.join("\n")
    fd.puts "map #{t.length}", t

    t = @decoded.map { |a, d|
      next if not d.kind_of? DecodedInstruction
      "#{Expression[a]},#{d.bin_length} #{d.instruction}#{" ; #{d.comment.join(' ')}" if d.comment}"
    }.compact.sort.join("\n")
    fd.puts "decoded #{t.length}", t

    t = @comment.map { |a, c|
      c.map { |l| l.chomp }.join("\n").split("\n").map { |lc| "#{Expression[a]} #{lc.chomp}" }
    }.join("\n")
    fd.puts "comment #{t.length}", t

    bl = @decoded.values.map { |d|
      d.block if d.kind_of? DecodedInstruction and d.block_head?
    }.compact
    t = bl.map { |b|
      [Expression[b.address],
       b.list.map { |d| Expression[d.address] }.join(','),
       b.to_normal.to_a.map { |t_| Expression[t_] }.join(','),
       b.to_subfuncret.to_a.map { |t_| Expression[t_] }.join(','),
       b.to_indirect.to_a.map { |t_| Expression[t_] }.join(','),
       b.from_normal.to_a.map { |t_| Expression[t_] }.join(','),
       b.from_subfuncret.to_a.map { |t_| Expression[t_] }.join(','),
       b.from_indirect.to_a.map { |t_| Expression[t_] }.join(','),
      ].join(';')
    }.sort.join("\n")
    fd.puts "blocks #{t.length}", t

    t = @function.map { |a, f|
      next if not @decoded[a]
      [a, *f.return_address.to_a].map { |e| Expression[e] }.join(',')
    }.compact.sort.join("\n")
    # TODO binding ?
    fd.puts "funcs #{t.length}", t

    t = @xrefs.map { |a, x|
      a = ':default' if a == :default
      a = ':unknown' if a == Expression::Unknown
      # XXX origin
      case x
      when nil
      when Xref
        [Expression[a], x.type, x.len, (Expression[x.origin] if x.origin)].join(',')
      when Array
        x.map { |x_| [Expression[a], x_.type, x_.len, (Expression[x_.origin] if x_.origin)].join(',') }
      end
    }.compact.join("\n")
    fd.puts "xrefs #{t.length}", t

    t = @c_parser.to_s
    fd.puts "c #{t.length}", t

    #t = bl.map { |b| b.backtracked_for }
    #fd.puts "trace #{t.length}" , t
  end

  # loads a disassembler from a saved file
  def self.load(str, &b)
    d = new(nil, nil)
    d.load(str, &b)
    d
  end

  # loads the dasm state from a savefile content
  # will yield unknown segments / binarypath notfound
  def load(str)
    raise 'Not a metasm save file' if str[0, 12].chomp != 'Metasm.dasm'
    off = 12
    pp = Preprocessor.new
    app = AsmPreprocessor.new
    while off < str.length
      i = str.index("\n", off) || str.length
      type, len = str[off..i].chomp.split
      off = i+1
      data = str[off, len.to_i]
      off += len.to_i
      case type
      when nil, ''
      when 'binarypath'
        data = yield(type, data) if not File.exist? data and block_given?
        reinitialize AutoExe.decode_file(data)
        @program.disassembler = self
        @program.init_disassembler
      when 'cpu'
        cpuname, size, endianness = data.split
        cpu = Metasm.const_get(cpuname)
        raise 'invalid cpu' if not cpu < CPU
        cpu = cpu.new
        cpu.size = size.to_i
        cpu.endianness = endianness.to_sym
        reinitialize Shellcode.new(cpu)
        @program.disassembler = self
        @program.init_disassembler
        @sections.delete(0)	# rm empty section at 0, other real 'section' follow
      when 'section'
        info = data[0, data.index("\n") || data.length]
        data = data[info.length, data.length]
        pp.feed!(info)
        addr = Expression.parse(pp).reduce
        len = Expression.parse(pp).reduce
        edata = EncodedData.new(data.unpack('m*').first, :virtsize => len)
        add_section(addr, edata)
      when 'map'
        load_map data
      when 'decoded'
        data.each_line { |l|
          begin
            next if l !~ /^([^,]*),(\d*) ([^;]*)(?:; (.*))?/
            a, len, instr, cmt = $1, $2, $3, $4
            a = Expression.parse(pp.feed!(a)).reduce
            instr = @cpu.parse_instruction(app.feed!(instr))
            di = DecodedInstruction.new(instr, a)
            di.bin_length = len.to_i
            di.add_comment cmt if cmt
            @decoded[a] = di
          rescue
            puts "load: bad di #{l.inspect}" if $VERBOSE
          end
        }
      when 'blocks'
        data.each_line { |l|
          bla = l.chomp.split(';').map { |sl| sl.split(',') }
          begin
            a = Expression.parse(pp.feed!(bla.shift[0])).reduce
            b = InstructionBlock.new(a, get_section_at(a).to_a[0])
            bla.shift.each { |e|
              a = Expression.parse(pp.feed!(e)).reduce
              b.add_di(@decoded[a])
            }
            bla.zip([:to_normal, :to_subfuncret, :to_indirect, :from_normal, :from_subfuncret, :from_indirect]).each { |l_, s|
              b.send("#{s}=", l_.map { |e| Expression.parse(pp.feed!(e)).reduce }) if not l_.empty?
            }
          rescue
            puts "load: bad block #{l.inspect}" if $VERBOSE
          end
        }
      when 'funcs'
        data.each_line { |l|
          begin
            a, *r = l.split(',').map { |e| Expression.parse(pp.feed!(e)).reduce }
            @function[a] = DecodedFunction.new
            @function[a].return_address = r if not r.empty?
            @function[a].finalized = true
            # TODO
          rescue
            puts "load: bad function #{l.inspect} #$!" if $VERBOSE
          end
        }
      when 'comment'
        data.each_line { |l|
          begin
            a, c = l.split(' ', 2)
            a = Expression.parse(pp.feed!(a)).reduce
            @comment[a] ||= []
            @comment[a] |= [c]
          rescue
            puts "load: bad comment #{l.inspect} #$!" if $VERBOSE
          end
        }
      when 'c'
        begin
          # TODO parse_invalid_c, split per function, whatever
          parse_c('')
          @c_parser.allow_bad_c = true
          parse_c(data, 'savefile#c')
        rescue
          puts "load: bad C: #$!", $!.backtrace if $VERBOSE
        end
        @c_parser.readtok until @c_parser.eos? if @c_parser
      when 'xrefs'
        data.each_line { |l|
          begin
            a, t, len, o = l.chomp.split(',')
            case a
            when ':default'; a = :default
            when ':unknown'; a = Expression::Unknown
            else a = Expression.parse(pp.feed!(a)).reduce
            end
            t = (t.empty? ? nil : t.to_sym)
            len = (len != '' ? len.to_i : nil)
            o = (o.to_s != '' ? Expression.parse(pp.feed!(o)).reduce : nil)	# :default/:unknown ?
            add_xref(a, Xref.new(t, o, len))
          rescue
            puts "load: bad xref #{l.inspect} #$!" if $VERBOSE
          end
        }
      #when 'trace'
      else
        if block_given?
          yield(type, data)
        else
          puts "load: unsupported section #{type.inspect}" if $VERBOSE
        end
      end
    end
  end

  # change the base address of the loaded binary
  # better done early (before disassembling anything)
  # returns the delta
  def rebase(newaddr)
    rebase_delta(newaddr - @sections.keys.min)
  end

  def rebase_delta(delta)
    fix = lambda { |a|
      case a
      when Array
        a.map! { |e| fix[e] }
      when Hash
        tmp = {}
        a.each { |k, v| tmp[fix[k]] = v }
        a.replace tmp
      when Integer
        a += delta
      when BacktraceTrace
        a.origin = fix[a.origin]
        a.address = fix[a.address]
      end
      a
    }

    fix[@sections]
    fix[@decoded]
    fix[@xrefs]
    fix[@function]
    fix[@addrs_todo]
    fix[@addrs_done]
    fix[@comment]
    @prog_binding.each_key { |k| @prog_binding[k] = fix[@prog_binding[k]] }
    @old_prog_binding.each_key { |k| @old_prog_binding[k] = fix[@old_prog_binding[k]] }
    @label_alias_cache = nil

    @decoded.values.grep(DecodedInstruction).each { |di|
      if di.block_head?
        b = di.block
        b.address += delta
        fix[b.to_normal]
        fix[b.to_subfuncret]
        fix[b.to_indirect]
        fix[b.from_normal]
        fix[b.from_subfuncret]
        fix[b.from_indirect]
        fix[b.backtracked_for]
      end
      di.address = fix[di.address]
      di.next_addr = fix[di.next_addr]
    }
    @function.each_value { |f|
      f.return_address = fix[f.return_address]
      fix[f.backtracked_for]
    }
    @xrefs.values.flatten.compact.each { |x| x.origin = fix[x.origin] }
    delta
  end

  # dataflow method
  # walks a function, starting at addr
  # follows the usage of registers, computing the evolution from the value they had at start_addr
  # whenever an instruction references the register (or anything derived from it),
  #  yield [di, used_register, reg_value, trace_state] where reg_value is the Expression holding the value of
  #  the register wrt the initial value at start_addr, and trace_state the value of all registers (reg_value
  #  not yet applied)
  #  reg_value may be nil if used_register is not modified by the function (eg call [eax])
  #  the yield return value is propagated, unless it is nil/false
  # init_state is a hash { :reg => initial value }
  def trace_function_register(start_addr, init_state)
    function_walk(start_addr, init_state) { |args|
      trace_state = args.last
      case args.first
      when :di
        di = args[2]
        update = {}
        get_fwdemu_binding(di).each { |r, v|
          if v.kind_of?(Expression) and v.externals.find { |e| trace_state[e] }
            # XXX may mix old (from trace) and current (from v) registers
            newv = v.bind(trace_state)
            update[r] = yield(di, r, newv, trace_state)
          elsif r.kind_of?(ExpressionType) and rr = r.externals.find { |e| trace_state[e] }
            # reg dereferenced in a write (eg mov [esp], 42)
            next if update.has_key?(rr)	# already yielded
            if yield(di, rr, trace_state[rr], trace_state) == false
              update[rr] = false
            end
          elsif trace_state[r]
            # started on mov reg, foo
            next if di.address == start_addr
            update[r] = false
          end
        }

        # directly walk the instruction argument list for registers not appearing in the binding
        @cpu.instr_args_memoryptr(di).each { |ind|
          b = @cpu.instr_args_memoryptr_getbase(ind)
          if b and b = b.symbolic and not update.has_key?(b)
            yield(di, b, nil, trace_state)
          end
        }
        @cpu.instr_args_regs(di).each { |r|
          r = r.symbolic
          if not update.has_key?(r)
            yield(di, r, nil, trace_state)
          end
        }

        update.each { |r, v|
          trace_state = trace_state.dup
          if v
            # cannot follow non-registers, or we would have to emulate every single
            # instruction (try following [esp+4] across a __stdcall..)
            trace_state[r] = v if r.kind_of?(::Symbol)
          else
            trace_state.delete r
          end
        }
      when :subfunc
        faddr = args[1]
        f = @function[faddr]
        f = @function[f.backtrace_binding[:thunk]] if f and f.backtrace_binding[:thunk]
        if f
          binding = f.backtrace_binding
          if binding.empty?
            backtrace_update_function_binding(faddr)
            binding = f.backtrace_binding
          end
          # XXX fwdemu_binding ?
          binding.each { |r, v|
            if v.externals.find { |e| trace_state[e] }
              if r.kind_of?(::Symbol)
                trace_state = trace_state.dup
                trace_state[r] = Expression[v.bind(trace_state)].reduce
              end
            elsif trace_state[r]
              trace_state = trace_state.dup
              trace_state.delete r
            end
          }
        end
      when :merge
        # when merging paths, keep the smallest common state subset
        # XXX may have unexplored froms
        conflicts = args[2]
        trace_state = trace_state.dup
        conflicts.each { |addr, st|
          trace_state.delete_if { |k, v| st[k] != v }
        }
      end
      trace_state = false if trace_state.empty?
      trace_state
    }
  end

  # define a register as a pointer to a structure
  # rename all [reg+off] as [reg+struct.member] in current function
  # also trace assignments of pointer members
  def trace_update_reg_structptr(addr, reg, structname, structoff=0)
    sname = soff = ctx = nil
    expr_to_sname = lambda { |expr|
      if not expr.kind_of?(Expression) or expr.op != :+
        sname = nil
        next
      end

      sname = expr.lexpr || expr.rexpr
      soff = (expr.lexpr ? expr.rexpr : 0)

      if soff.kind_of?(Expression)
        # ignore index in ptr array
        if soff.op == :* and soff.lexpr == @cpu.size/8
          soff = 0
        elsif soff.rexpr.kind_of?(Expression) and soff.rexpr.op == :* and soff.rexpr.lexpr == @cpu.size/8
          soff = soff.lexpr
        elsif soff.lexpr.kind_of?(Expression) and soff.lexpr.op == :* and soff.lexpr.lexpr == @cpu.size/8
          soff = soff.rexpr
        end
      elsif soff.kind_of?(::Symbol)
        # array with 1 byte elements / pre-scaled idx?
        if not ctx[soff]
          soff = 0
        end
      end
    }

    lastdi = nil
    trace_function_register(addr, reg => Expression[structname, :+, structoff]) { |di, r, val, trace|

      next if r.to_s =~ /flag/	# XXX maybe too ia32-specific?

      ctx = trace
      @cpu.instr_args_memoryptr(di).each { |ind|
        # find the structure dereference in di
        b = @cpu.instr_args_memoryptr_getbase(ind)
        b = b.symbolic if b
        next unless trace[b]
        imm = @cpu.instr_args_memoryptr_getoffset(ind) || 0

        # check expr has the form 'traced_struct_reg + off'
        expr_to_sname[trace[b] + imm]	# Expr#+ calls Expr#reduce
        next unless sname.kind_of?(::String) and soff.kind_of?(::Integer)
        next if not st = c_parser.toplevel.struct[sname] or not st.kind_of?(C::Union)

        # ignore lea esi, [esi+0]
        next if soff == 0 and not di.backtrace_binding.find { |k, v| v-k != 0 }

        # TODO if trace[b] offset != 0, we had a lea reg, [struct+substruct_off], tweak str accordingly

        # resolve struct + off into struct.membername
        str = st.name.dup
        mb = st.expand_member_offset(c_parser, soff, str)
        # patch di
        imm = imm.rexpr if imm.kind_of?(Expression) and not imm.lexpr and imm.rexpr.kind_of?(ExpressionString)
        imm = imm.expr if imm.kind_of?(ExpressionString)
        @cpu.instr_args_memoryptr_setoffset(ind, ExpressionString.new(imm, str, :structoff))

        # check if the type is an enum/bitfield, patch instruction immediates
        trace_update_reg_structptr_arg_enum(di, ind, mb, str) if mb
      } if lastdi != di.address
      lastdi = di.address

      next Expression[structname, :+, structoff] if di.address == addr and r == reg

      # check if we need to trace 'r' further
      val = val.reduce_rec if val.kind_of?(Expression)
      val = Expression[val] if val.kind_of?(::String)
      case val
      when Expression
        # only trace trivial structptr+off expressions
        expr_to_sname[val]
        if sname.kind_of?(::String) and soff.kind_of?(::Integer)
          Expression[sname, :+, soff]
        end

      when Indirection
        # di is mov reg, [ptr+struct.offset]
        # check if the target member is a pointer to a struct, if so, trace it
        expr_to_sname[val.pointer.reduce]

        next unless sname.kind_of?(::String) and soff.kind_of?(::Integer)

        if st = c_parser.toplevel.struct[sname] and st.kind_of?(C::Union)
          pt = st.expand_member_offset(c_parser, soff, '')
          pt = pt.untypedef if pt
          if pt.kind_of?(C::Pointer)
            tt = pt.type.untypedef
            stars = ''
            while tt.kind_of?(C::Pointer)
              stars << '*'
              tt = tt.type.untypedef
            end
            if tt.kind_of?(C::Union) and tt.name
              Expression[tt.name + stars]
            end
          end

        elsif soff == 0 and sname[-1] == ?*
          # XXX pointer to pointer to struct
          # full C type support would be better, but harder to fit in an Expr
          Expression[sname[0...-1]]
        end
      # in other cases, stop trace
      end
    }
  end

  # found a special member of a struct, check if we can apply
  # bitfield/enum name to other constants in the di
  def trace_update_reg_structptr_arg_enum(di, ind, mb, str)
    if ename = mb.has_attribute_var('enum') and enum = c_parser.toplevel.struct[ename] and enum.kind_of?(C::Enum)
      # handle enums: struct moo { int __attribute__((enum(bla))) fld; };
      doit = lambda { |_di|
        if num = _di.instruction.args.grep(Expression).first and num_i = num.reduce and num_i.kind_of?(::Integer)
          # handle enum values on tagged structs
          if enum.members and name = enum.members.index(num_i)
            num.lexpr = nil
            num.op = :+
            num.rexpr = ExpressionString.new(Expression[num_i], name, :enum)
            _di.add_comment "enum::#{ename}" if _di.address != di.address
          end
        end
      }

      doit[di]

      # mov eax, [ptr+struct.enumfield]  =>  trace eax
      if reg = @cpu.instr_args_regs(di).find { |r| v = di.backtrace_binding[r.symbolic] and (v - ind.symbolic) == 0 }
        reg = reg.symbolic
        trace_function_register(di.address, reg => Expression[0]) { |_di, r, val, trace|
          next if r != reg and val != Expression[reg]
          doit[_di]
          val
        }
      end

    elsif mb.untypedef.kind_of?(C::Struct)
      # handle bitfields

      byte_off = 0
      if str =~ /\+(\d+)$/
        # test byte [bitfield+1], 0x1  =>  test dword [bitfield], 0x100
        # XXX little-endian only
        byte_off = $1.to_i
        str[/\+\d+$/] = ''
      end
      cmt = str.split('.')[-2, 2].join('.') if str.count('.') > 1

      doit = lambda { |_di, add|
        if num = _di.instruction.args.grep(Expression).first and num_i = num.reduce and num_i.kind_of?(::Integer)
          # TODO handle ~num_i
          num_left = num_i << add
          s_or = []
          mb.untypedef.members.each { |mm|
            if bo = mb.bitoffsetof(c_parser, mm)
              boff, blen = bo
              if mm.name && blen == 1 && ((num_left >> boff) & 1) > 0
                s_or << mm.name
                num_left &= ~(1 << boff)
              end
            end
          }
          if s_or.first
            if num_left != 0
              s_or << ('0x%X' % num_left)
            end
            s = s_or.join('|')
            num.lexpr = nil
            num.op = :+
            num.rexpr = ExpressionString.new(Expression[num_i], s, :bitfield)
            _di.add_comment cmt if _di.address != di.address
          end
        end
      }

      doit[di, byte_off*8]

      if reg = @cpu.instr_args_regs(di).find { |r| v = di.backtrace_binding[r.symbolic] and (v - ind.symbolic) == 0 }
        reg = reg.symbolic
        trace_function_register(di.address, reg => Expression[0]) { |_di, r, val, trace|
          if r.kind_of?(Expression) and r.op == :&
                 if r.lexpr == reg
                   # test al, 42
                   doit[_di, byte_off*8]
                 elsif r.lexpr.kind_of?(Expression) and r.lexpr.op == :>> and r.lexpr.lexpr == reg
                   # test ah, 42
                   doit[_di, byte_off*8+r.lexpr.rexpr]
                 end
          end
          next if r != reg and val != Expression[reg]
          doit[_di, byte_off*8]
          _di.address == di.address && r == reg ? Expression[0] : val
        }
      end
    end
  end

  # change Expression display mode for current object o to display integers as char constants
  def toggle_expr_char(o)
    return if not o.kind_of?(Renderable)
    tochars = lambda { |v|
      if v.kind_of?(::Integer)
        a = []
        vv = v.abs
        a << (vv & 0xff)
        vv >>= 8
        while vv > 0
          a << (vv & 0xff)
          vv >>= 8
        end
        if a.all? { |b| b < 0x7f }
          s = a.pack('C*').inspect.gsub("'") { '\\\'' }[1...-1]
          ExpressionString.new(v, (v > 0 ? "'#{s}'" : "-'#{s}'"), :char)
        end
      end
    }
    o.each_expr { |e|
      if e.kind_of?(Expression)
        if nr = tochars[e.rexpr]
          e.rexpr = nr
        elsif e.rexpr.kind_of?(ExpressionString) and e.rexpr.type == :char
          e.rexpr = e.rexpr.expr
        end
        if nl = tochars[e.lexpr]
          e.lexpr = nl
        elsif e.lexpr.kind_of?(ExpressionString) and e.lexpr.type == :char
          e.lexpr = e.lexpr.expr
        end
      end
    }
  end

  def toggle_expr_dec(o)
    return if not o.kind_of?(Renderable)
    o.each_expr { |e|
      if e.kind_of?(Expression)
        if e.rexpr.kind_of?(::Integer)
          e.rexpr = ExpressionString.new(Expression[e.rexpr], e.rexpr.to_s, :decimal)
        elsif e.rexpr.kind_of?(ExpressionString) and e.rexpr.type == :decimal
          e.rexpr = e.rexpr.reduce
        end
        if e.lexpr.kind_of?(::Integer)
          e.lexpr = ExpressionString.new(Expression[e.lexpr], e.lexpr.to_s, :decimal)
        elsif e.lexpr.kind_of?(ExpressionString) and e.lexpr.type == :decimal
          e.lexpr = e.lexpr.reduce
        end
      end
    }
  end

  # patch Expressions in current object to include label names when available
  # XXX should we also create labels ?
  def toggle_expr_offset(o)
    return if not o.kind_of? Renderable
    o.each_expr { |e|
      next unless e.kind_of?(Expression)
      if n = @prog_binding[e.lexpr]
        e.lexpr = n
      elsif e.lexpr.kind_of? ::Integer and n = get_label_at(e.lexpr)
        add_xref(normalize(e.lexpr), Xref.new(:addr, o.address)) if o.respond_to? :address
        e.lexpr = n
      end
      if n = @prog_binding[e.rexpr]
        e.rexpr = n
      elsif e.rexpr.kind_of? ::Integer and n = get_label_at(e.rexpr)
        add_xref(normalize(e.rexpr), Xref.new(:addr, o.address)) if o.respond_to? :address
        e.rexpr = n
      end
    }
  end

  # toggle all ExpressionStrings
  def toggle_expr_str(o)
    return if not o.kind_of?(Renderable)
    o.each_expr { |e|
      next unless e.kind_of?(ExpressionString)
      e.hide_str = !e.hide_str
    }
  end

  # call this function on a function entrypoint if the function is in fact a __noreturn
  # will cut the to_subfuncret of callers
  def fix_noreturn(o)
    each_xref(o, :x) { |a|
      a = normalize(a.origin)
      next if not di = di_at(a) or not di.opcode.props[:saveip]
      # XXX should check if caller also becomes __noreturn
      di.block.each_to_subfuncret { |to|
        next if not tdi = di_at(to) or not tdi.block.from_subfuncret
        tdi.block.from_subfuncret.delete_if { |aa| normalize(aa) == di.address }
        tdi.block.from_subfuncret = nil if tdi.block.from_subfuncret.empty?
      }
      di.block.to_subfuncret = nil
    }
  end

  # find the addresses of calls calling the address, handles thunks
  def call_sites(funcaddr)
    find_call_site = proc { |a|
      until not di = di_at(a)
        if di.opcode.props[:saveip]
          cs = di.address
          break
        end
        if di.block.from_subfuncret.to_a.first
          while di.block.from_subfuncret.to_a.length == 1
            a = di.block.from_subfuncret[0]
            break if not di_at(a)
            a = @decoded[a].block.list.first.address
            di = @decoded[a]
          end
        end
        break if di.block.from_subfuncret.to_a.first
        break if di.block.from_normal.to_a.length != 1
        a = di.block.from_normal.first
      end
      cs
    }
    ret = []
    each_xref(normalize(funcaddr), :x) { |a|
      ret << find_call_site[a.origin]
    }
    ret.compact.uniq
  end

  # loads a disassembler plugin script
  # this is simply a ruby script instance_eval() in the disassembler
  # the filename argument is autocompleted with '.rb' suffix, and also
  #  searched for in the Metasmdir/samples/dasm-plugins subdirectory if not found in cwd
  def load_plugin(plugin_filename)
    if not File.exist?(plugin_filename)
      if File.exist?(plugin_filename+'.rb')
        plugin_filename += '.rb'
      elsif defined? Metasmdir
        # try autocomplete
        pf = File.join(Metasmdir, 'samples', 'dasm-plugins', plugin_filename)
        if File.exist? pf
          plugin_filename = pf
        elsif File.exist? pf + '.rb'
          plugin_filename = pf + '.rb'
        end
      end
    end

    instance_eval File.read(plugin_filename)
  end

  # same as load_plugin, but hides the @gui attribute while loading, preventing the plugin do popup stuff
  # this is useful when you want to load a plugin from another plugin to enhance the plugin's functionnality
  # XXX this also prevents setting up kbd_callbacks etc..
  def load_plugin_nogui(plugin_filename)
    oldgui = gui
    @gui = nil
    load_plugin(plugin_filename)
  ensure
    @gui = oldgui
  end

  # compose two code/instruction's backtrace_binding
  # assumes bd1 is followed by bd2 in the code flow
  # eg inc edi + push edi =>
  #  { Ind[:esp, 4] => Expr[:edi + 1], :esp => Expr[:esp - 4], :edi => Expr[:edi + 1] }
  # XXX if bd1 writes to memory with a pointer that is reused in bd2, this function has to
  # revert the change made by bd2, which only works with simple ptr addition now
  # XXX unhandled situations may be resolved using :unknown, or by returning incorrect values
  def compose_bt_binding(bd1, bd2)
    if bd1.kind_of? DecodedInstruction
      bd1 = bd1.backtrace_binding ||= cpu.get_backtrace_binding(bd1)
    end
    if bd2.kind_of? DecodedInstruction
      bd2 = bd2.backtrace_binding ||= cpu.get_backtrace_binding(bd2)
    end

    reduce = lambda { |e| Expression[Expression[e].reduce] }

    bd = {}

    bd2.each { |k, v|
      bd[k] = reduce[v.bind(bd1)]
    }

    # for each pointer appearing in keys of bd1, we must infer from bd2 what final
    # pointers should appear in bd
    # eg 'mov [eax], 0  mov ebx, eax'  => { [eax] <- 0, [ebx] <- 0, ebx <- eax }
    bd1.each { |k, v|
      if k.kind_of? Indirection
        done = false
        k.pointer.externals.each { |e|
          # XXX this will break on nontrivial pointers or bd2
          bd2.each { |k2, v2|
            # we dont want to invert computation of flag_zero/carry etc (booh)
            next if k2.to_s =~ /flag/

            # discard indirection etc, result would be too complex / not useful
            next if not Expression[v2].expr_externals.include? e

            done = true

            # try to reverse the computation made upon 'e'
            # only simple addition handled here
            ptr = reduce[k.pointer.bind(e => Expression[[k2, :-, v2], :+, e])]

            # if bd2 does not rewrite e, duplicate the original pointer
            if not bd2[e]
              bd[k] ||= reduce[v]

              # here we should not see 'e' in ptr anymore
              ptr = Expression::Unknown if ptr.externals.include? e
            else
              # cant check if add reversion was successful..
            end

            bd[Indirection[reduce[ptr], k.len]] ||= reduce[v]
          }
        }
        bd[k] ||= reduce[v] if not done
      else
        bd[k] ||= reduce[v]
      end
    }

    bd
  end

  def gui_hilight_word_regexp(word)
    @cpu.gui_hilight_word_regexp(word)
  end

  # return a C::AllocCStruct from c_parser
  # TODO handle program.class::Header.to_c_struct
  def decode_c_struct(structname, addr)
    if c_parser and edata = get_edata_at(addr)
      c_parser.decode_c_struct(structname, edata.data, edata.ptr)
    end
  end

  def decode_c_ary(structname, addr, len)
    if c_parser and edata = get_edata_at(addr)
      c_parser.decode_c_ary(structname, len, edata.data, edata.ptr)
    end
  end

  # find the function containing addr, and find & rename stack vars in it
  def name_local_vars(addr)
    if @cpu.respond_to?(:name_local_vars) and faddr = find_function_start(addr)
      @function[faddr] ||= DecodedFunction.new	# XXX
      @cpu.name_local_vars(self, faddr)
    end
  end
end
end
