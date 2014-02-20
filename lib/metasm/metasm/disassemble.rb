#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/decode'


module Metasm
# holds information for decoded instructions: the original opcode, a pointer to the InstructionBlock, etc
class DecodedInstruction
  # the instance of InstructionBlock this di is into
  attr_accessor :block
  # our offset (in bytes) from the start of the block, used only for hexdump
  attr_accessor :block_offset
  # the address of the instruction's first byte in memory
  attr_accessor :address
  # the disassembled data
  attr_accessor :instruction, :opcode
  # our, length in bytes
  attr_accessor :bin_length
  # array of arbitrary strings
  attr_accessor :comment
  # a cache of the binding used by the backtracker to emulate this instruction
  attr_accessor :backtrace_binding

  # create a new DecodedInstruction with an Instruction whose cpu is the argument
  # can take an existing Instruction as argument
  def initialize(arg, addr=nil)
    case arg
    when Instruction
      @instruction = arg
      @opcode = @instruction.cpu.opcode_list.find { |op| op.name == @instruction.opname } if @instruction.cpu
    else @instruction = Instruction.new(arg)
    end
    @bin_length = 0
    @address = addr if addr
  end

  def next_addr=(a) @next_addr = a end
  def next_addr
    (@next_addr ||= nil) || (address + @bin_length) if address
  end

  def show
    if block
      bin = @block.edata.data[@block.edata_ptr+@block_offset, @bin_length].unpack('C*').map { |c| '%02x' % c }.join
      if @bin_length > 12
        bin = bin[0, 20] + "..<+#{@bin_length-10}>"
      end
      "    #{@instruction.to_s.ljust(44)} ; @#{Expression[address]}  #{bin}  #{@comment.sort[0,6].join(' ') if comment}"
    else
      "#{@instruction}#{' ; ' + @comment.join(' ') if comment}"
    end
  end

  include Renderable
  def render
    ret = []
    ret << Expression[address] << ' ' if address
    ret << @instruction
    ret << ' ; ' << @comment if comment
    ret
  end

  def add_comment(c)
    @comment ||= []
    @comment |= [c]
  end

  # returns a copy of the DecInstr, with duplicated #instruction ("deep_copy")
  def dup
    new = super()
    new.instruction = @instruction.dup
    new
  end
end

# holds information on a backtracked expression near begin and end of instruction blocks (#backtracked_for)
class BacktraceTrace
  # address of the instruction in the block from which rebacktrace should start (use with from_subfuncret bool)
  # address is nil if the backtrace is from block start
  # exclude_instr is a bool saying if the backtrace should start at address or at the preceding instruction
  # these are optional: if absent, expr is to be rebacktracked when a new codepath arrives at the beginning of the block
  attr_accessor :address, :from_subfuncret, :exclude_instr
  # address of the instruction that initiated the backtrace
  attr_accessor :origin
  # the Expression to backtrace at this point
  attr_accessor :expr
  # the original backtracked Expression
  attr_accessor :orig_expr
  # length of r/w xref (in bytes)
  attr_accessor :len
  # :r/:w/:x
  attr_accessor :type
  # bool: true if this maps to a :x that should not have a from when resolved
  attr_accessor :detached
  # maxdepth at the point of the object creation
  attr_accessor :maxdepth

  def initialize(expr, origin, orig_expr, type, len=nil, maxdepth=nil)
    @expr, @origin, @orig_expr, @type = expr, origin, orig_expr, type
    @len = len if len
    @maxdepth = maxdepth if maxdepth
  end

  def hash ; [origin, expr].hash ; end
  def eql?(o)
    o.class == self.class and
    [  address,   from_subfuncret,   exclude_instr,   origin,   orig_expr,   len,   type,   detached] ==
    [o.address, o.from_subfuncret, o.exclude_instr, o.origin, o.orig_expr, o.len, o.type, o.detached]
  end
  alias == eql?
end

# a cross-reference, tracks read/write/execute memory accesses by decoded instructions
class Xref
  # :r/:w/:x
  attr_accessor :type
  # length of r/w (in bytes)
  attr_accessor :len
  # address of the instruction responsible of the xref
  attr_accessor :origin
  # XXX list of instructions intervening in the backtrace ?

  def initialize(type, origin, len=nil)
    @origin, @type = origin, type
    @len = len if len
  end

  def hash ; @origin.hash ; end
  def eql?(o) o.class == self.class and [type, len, origin] == [o.type, o.len, o.origin] end
  alias == eql?
end

# holds a list of contiguous decoded instructions, forming an uninterrupted block (except for eg CPU exceptions)
# most attributes are either a value or an array of values, use the associated iterator.
class InstructionBlock
  # address of the first instruction
  attr_accessor :address
  # pointer to raw data
  attr_accessor :edata, :edata_ptr
  # list of DecodedInstructions
  attr_accessor :list
  # address of instructions giving control directly to us
  # includes addr of normal instruction when call flow continues to us past the end of the preceding block
  # does not include addresses of subfunction return instructions
  # may be nil or an array
  attr_accessor :from_normal
  # address of instructions called/jumped to
  attr_accessor :to_normal
  # address of an instruction that calls a subfunction which returns to us
  attr_accessor :from_subfuncret
  # address of instruction executed after a called subfunction returns
  attr_accessor :to_subfuncret
  # address of instructions executed indirectly through us (callback in a subfunction, SEH...)
  # XXX from_indirect is not populated for now
  attr_accessor :from_indirect, :to_indirect
  # array of BacktraceTrace
  # when a new code path comes to us, it should be backtracked for the values of :r/:w/:x using btt with no address
  # for internal use only (block splitting): btt with an address
  attr_accessor :backtracked_for

  # create a new InstructionBlock based at address
  # also accepts a DecodedInstruction or an Array of them to initialize from
  def initialize(arg0, edata=nil, edata_ptr=nil)
    @list = []
    case arg0
    when DecodedInstruction
      @address = arg0.address
      add_di(arg0)
    when Array
      @address = arg0.first.address if not arg0.empty?
      arg0.each { |di| add_di(di) }
    else
      @address = arg0
    end
    edata_ptr ||= edata ? edata.ptr : 0
    @edata, @edata_ptr = edata, edata_ptr
    @backtracked_for = []
  end

  def bin_length
    (di = @list.last) ? di.block_offset + di.bin_length : 0
  end

  # splits the current block into a new one with all di from address addr to end
  # caller is responsible for rebacktracing new.bt_for to regenerate correct old.btt/new.btt
  def split(addr)
    raise "invalid split @#{Expression[addr]}" if not idx = @list.index(@list.find { |di| di.address == addr }) or idx == 0
    off = @list[idx].block_offset
    new_b = self.class.new(addr, @edata, @edata_ptr + off)
    new_b.add_di @list.delete_at(idx) while @list[idx]
    new_b.to_normal, @to_normal = to_normal, new_b.to_normal
    new_b.to_subfuncret, @to_subfuncret = to_subfuncret, new_b.to_subfuncret
    new_b.add_from @list.last.address
    add_to new_b.address
    @backtracked_for.delete_if { |btt|
      if btt.address and new_b.list.find { |di| di.address == btt.address }
        new_b.backtracked_for << btt
        true
      end
    }
    new_b
  end

  # adds a decodedinstruction to the block list, updates di.block and di.block_offset
  def add_di(di)
    di.block = self
    di.block_offset = bin_length
    di.address ||= @address + di.block_offset
    @list << di
  end
end

# a factorized subfunction as seen by the disassembler
class DecodedFunction
  # when backtracking an instruction that calls us, use this binding and then the instruction's
  # the binding is lazily filled up for non-external functions, register by register, when
  # a backtraced expression depends on it
  attr_accessor :backtrace_binding
  # same as InstructionBlock#backtracked_for
  # includes the expression responsible of the function return (eg [esp] on ia32)
  attr_accessor :backtracked_for
  # addresses of instruction causing the function to return
  attr_accessor :return_address
  # a lambda called for dynamic backtrace_binding generation
  attr_accessor :btbind_callback
  # a lambda called for dynamic backtracked_for
  attr_accessor :btfor_callback
  # bool, if false the function is actually being disassembled
  attr_accessor :finalized
  # bool, if true the function does not return (eg exit() or ExitProcess())
  attr_accessor :noreturn

  # if btbind_callback is defined, calls it with args [dasm, binding, funcaddr, calladdr, expr, origin, maxdepth]
  # else update lazily the binding from expr.externals, and return backtrace_binding
  def get_backtrace_binding(dasm, funcaddr, calladdr, expr, origin, maxdepth)
    if btbind_callback
      @btbind_callback[dasm, @backtrace_binding, funcaddr, calladdr, expr, origin, maxdepth]
    elsif backtrace_binding and dest = @backtrace_binding[:thunk] and target = dasm.function[dest]
      target.get_backtrace_binding(dasm, funcaddr, calladdr, expr, origin, maxdepth)
    else
      unk_regs = expr.externals.grep(Symbol).uniq - @backtrace_binding.keys - [:unknown]
      dasm.cpu.backtrace_update_function_binding(dasm, funcaddr, self, return_address, *unk_regs) if not unk_regs.empty?
      @backtrace_binding
    end
  end

  # if btfor_callback is defined, calls it with args [dasm, bt_for, funcaddr, calladdr]
  # else return backtracked_for
  def get_backtracked_for(dasm, funcaddr, calladdr)
    if btfor_callback
      @btfor_callback[dasm, @backtracked_for, funcaddr, calladdr]
    elsif backtrace_binding and dest = @backtrace_binding[:thunk] and target = dasm.function[dest]
      target.get_backtracked_for(dasm, funcaddr, calladdr)
    else
      @backtracked_for
    end
  end

  def initialize
    @backtracked_for = []
    @backtrace_binding = {}
  end
end

class CPU
  # return the thing to backtrace to find +value+ before the execution of this instruction
  # eg backtrace_emu('inc eax', Expression[:eax]) => Expression[:eax + 1]
  #  (the value of :eax after 'inc eax' is the value of :eax before plus 1)
  # may return Expression::Unknown
  def backtrace_emu(di, value)
    Expression[Expression[value].bind(di.backtrace_binding ||= get_backtrace_binding(di)).reduce]
  end

  # returns a list of Expressions/Integer to backtrace to find an execution target
  def get_xrefs_x(dasm, di)
  end

  # returns a list of [type, address, len]
  def get_xrefs_rw(dasm, di)
    get_xrefs_r(dasm, di).map { |addr, len| [:r, addr, len] } + get_xrefs_w(dasm, di).map { |addr, len| [:w, addr, len] }
  end

  # returns a list [addr, len]
  def get_xrefs_r(dasm, di)
    b = di.backtrace_binding ||= get_backtrace_binding(di)
    r = b.values
    x = get_xrefs_x(dasm, di)
    r |= x if x
    (r.grep(Indirection) + r.grep(Expression).map { |e| e.expr_indirections }.flatten).map { |e| [e.target, e.len] }
  end

  # returns a list [addr, len]
  def get_xrefs_w(dasm, di)
    b = di.backtrace_binding ||= get_backtrace_binding(di)
    w = b.keys
    (w.grep(Indirection) + w.grep(Expression).map { |e| e.expr_indirections }.flatten).map { |e| [e.target, e.len] }
  end

  # checks if the expression corresponds to a function return value with the instruction
  # (eg di == 'call something' and expr == [esp])
  def backtrace_is_function_return(expr, di=nil)
  end

  # updates f.backtrace_binding when a new return address has been found
  # TODO update also when anything changes inside the function (new loop found etc) - use backtracked_for ?
  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
  end

  # returns if the expression is an address on the stack
  # (to avoid trying to backtrace its absolute address until we found function boundaries)
  def backtrace_is_stack_address(expr)
  end

  # updates the instruction arguments: replace an expression with another (eg when a label is renamed)
  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; Expression[a.bind(old => new).reduce]
      else a
      end
    }
  end

  # a callback called whenever a backtrace is successful
  # di is the decodedinstruction at the backtrace's origin
  def backtrace_found_result(dasm, di, expr, type, len)
  end
end

class ExeFormat
  # returns a string containing asm-style section declaration
  def dump_section_header(addr, edata)
    "\n// section at #{Expression[addr]}"
  end

  # returns an array of expressions that may be executed by this instruction
  def get_xrefs_x(dasm, di)  @cpu.get_xrefs_x(dasm, di)  end

  # returns an array of [type, expression, length] that may be accessed by this instruction (type is :r/:w, len is in bytes)
  def get_xrefs_rw(dasm, di) @cpu.get_xrefs_rw(dasm, di) end
end

# a disassembler class
# holds a copy of a program sections, a list of decoded instructions, xrefs
# is able to backtrace an expression from an address following the call flow (backwards)
class Disassembler
  attr_accessor :program, :cpu
  # binding (jointure of @sections.values.exports)
  attr_accessor :prog_binding
  # hash addr => edata
  attr_accessor :sections
  # hash addr => DecodedInstruction
  attr_accessor :decoded
  # hash addr => DecodedFunction	 (includes 'imported' functions)
  attr_accessor :function
  # hash addr => (array of) xrefs - access with +add_xref+/+each_xref+
  attr_accessor :xrefs
  # bool, true to check write xrefs on each instr disasm (default true)
  attr_accessor :check_smc
  # list of [addr to disassemble, (optional)who jumped to it, (optional)got there by a subfunction return]
  attr_accessor :addrs_todo
  # hash address => binding
  attr_accessor :address_binding
  # number of blocks to backtrace before aborting if no result is found (defaults to class.backtrace_maxblocks, 50 by default)
  attr_accessor :backtrace_maxblocks
  # maximum backtrace length for :r/:w, defaults to backtrace_maxblocks
  attr_accessor :backtrace_maxblocks_data
  # max bt length for backtrace_fast blocks, default=0
  attr_accessor :backtrace_maxblocks_fast
  # max complexity for an Expr during backtrace before abort
  attr_accessor :backtrace_maxcomplexity, :backtrace_maxcomplexity_data
  # maximum number of instructions inside a basic block, split past this limit
  attr_accessor :disassemble_maxblocklength
  # a cparser that parsed some C header files, prototypes are converted to DecodedFunction when jumped to
  attr_accessor :c_parser
  # hash address => array of strings
  # default dasm dump will only show comments at beginning of code blocks
  attr_accessor :comment
  # bool, set to true (default) if functions with undetermined binding should be assumed to return with ABI-conforming binding (conserve frame ptr)
  attr_accessor :funcs_stdabi
  # callback called whenever an instruction will backtrace :x (before the backtrace is started)
  # arguments: |addr of origin, array of exprs to backtrace|
  # must return the replacement array, nil == []
  attr_accessor :callback_newaddr
  # called whenever an instruction is decoded and added to an instruction block. arg: the new decoded instruction
  # returns the new di to consider (nil to end block)
  attr_accessor :callback_newinstr
  # called whenever the disassembler tries to disassemble an addresse that has been written to. arg: the address
  attr_accessor :callback_selfmodifying
  # called when the disassembler stops (stopexec/undecodable instruction)
  attr_accessor :callback_stopaddr
  # callback called before each backtrace that may take some time
  attr_accessor :callback_prebacktrace
  # callback called once all addresses have been disassembled
  attr_accessor :callback_finished
  # pointer to the gui widget we're displayed in
  attr_accessor :gui

  @@backtrace_maxblocks = 50

  # creates a new disassembler
  def initialize(program, cpu=program.cpu)
    reinitialize(program, cpu)
  end

  # resets the program
  def reinitialize(program, cpu=program.cpu)
    @program = program
    @cpu = cpu
    @sections = {}
    @decoded = {}
    @xrefs = {}
    @function = {}
    @check_smc = true
    @prog_binding = {}
    @old_prog_binding = {}	# same as prog_binding, but keep old var names
    @addrs_todo = []
    @addrs_done = []
    @address_binding = {}
    @backtrace_maxblocks = @@backtrace_maxblocks
    @backtrace_maxblocks_fast = 0
    @backtrace_maxcomplexity = 40
    @backtrace_maxcomplexity_data = 5
    @disassemble_maxblocklength = 100
    @comment = {}
    @funcs_stdabi = true
  end

  # adds a section, updates prog_binding
  # base addr is an Integer or a String (label name for offset 0)
  def add_section(encoded, base)
    encoded, base = base, encoded if base.kind_of? EncodedData
    case base
    when ::Integer
    when ::String
      raise "invalid section base #{base.inspect} - not at section start" if encoded.export[base] and encoded.export[base] != 0
      raise "invalid section base #{base.inspect} - already seen at #{@prog_binding[base]}" if @prog_binding[base] and @prog_binding[base] != Expression[base]
      encoded.add_export base, 0
    else raise "invalid section base #{base.inspect} - expected string or integer"
    end

    @sections[base] = encoded
    @label_alias_cache = nil
    encoded.binding(base).each { |k, v|
      @old_prog_binding[k] = @prog_binding[k] = v.reduce
    }

    # update section_edata.reloc
    # label -> list of relocs that refers to it
    @inv_section_reloc = {}
    @sections.each { |b, e|
      e.reloc.each { |o, r|
        r.target.externals.grep(::String).each { |ext| (@inv_section_reloc[ext] ||= []) << [b, e, o, r] }
      }
    }

    self
  end

  def add_xref(addr, x)
    case @xrefs[addr]
    when nil; @xrefs[addr] = x
    when x
    when ::Array; @xrefs[addr] |= [x]
    else @xrefs[addr] = [@xrefs[addr], x]
    end
  end

  # yields each xref to a given address, optionnaly restricted to a type
  def each_xref(addr, type=nil)
    addr = normalize addr

    x = @xrefs[addr]
    x = case x
        when nil; []
        when ::Array; x.dup
        else [x]
        end

    x.delete_if { |x_| x_.type != type } if type

    # add pseudo-xrefs for exe relocs
    if (not type or type == :reloc) and l = get_label_at(addr) and a = @inv_section_reloc[l]
      a.each { |b, e, o, r|
        addr = Expression[b]+o
        # ignore relocs embedded in an already-listed instr
        x << Xref.new(:reloc, addr) if not x.find { |x_|
          next if not x_.origin or not di_at(x_.origin)
          (addr - x_.origin rescue 50) < @decoded[x_.origin].bin_length
        }
      }
    end

    x.each { |x_| yield x_ }
  end

  # parses a C header file, from which function prototypes will be converted to DecodedFunction when found in the code flow
  def parse_c_file(file)
    parse_c File.read(file), file
  end

  # parses a C string for function prototypes
  def parse_c(str, filename=nil, lineno=1)
    @c_parser ||= @cpu.new_cparser
    @c_parser.lexer.define_weak('__METASM__DECODE__')
    @c_parser.parse(str, filename, lineno)
  end

  # returns the canonical form of addr (absolute address integer or label of start of section + section offset)
  def normalize(addr)
    return addr if not addr or addr == :default
    addr = Expression[addr].bind(@old_prog_binding).reduce if not addr.kind_of? Integer
    addr %= 1 << [@cpu.size, 32].max if @cpu and addr.kind_of? Integer
    addr
  end

  # returns [edata, edata_base] or nil
  # edata.ptr points to addr
  def get_section_at(addr, memcheck=true)
    case addr = normalize(addr)
    when ::Integer
      if s =  @sections.find { |b, e| b.kind_of? ::Integer and addr >= b and addr < b + e.length } ||
        @sections.find { |b, e| b.kind_of? ::Integer and addr == b + e.length }		# end label
        s[1].ptr = addr - s[0]
        return if memcheck and s[1].data.respond_to?(:page_invalid?) and s[1].data.page_invalid?(s[1].ptr)
        [s[1], s[0]]
      end
    when Expression
      if addr.op == :+ and addr.rexpr.kind_of? ::Integer and addr.rexpr >= 0 and addr.lexpr.kind_of? ::String and e = @sections[addr.lexpr]
        e.ptr = addr.rexpr
        return if memcheck and e.data.respond_to?(:page_invalid?) and e.data.page_invalid?(e.ptr)
        [e, Expression[addr.lexpr]]
      elsif addr.op == :+ and addr.rexpr.kind_of? ::String and not addr.lexpr and e = @sections[addr.rexpr]
        e.ptr = 0
        return if memcheck and e.data.respond_to?(:page_invalid?) and e.data.page_invalid?(e.ptr)
        [e, addr.rexpr]
      end
    end
  end

  # returns the label at the specified address, creates it if needed using "prefix_addr"
  # renames the existing label if it is in the form rewritepfx_addr
  # returns nil if the address is not known and is not a string
  def auto_label_at(addr, base='xref', *rewritepfx)
    addr = Expression[addr].reduce
    addrstr = "#{base}_#{Expression[addr]}"
    return if addrstr !~ /^\w+$/
    e, b = get_section_at(addr)
    if not e
      l = Expression[addr].reduce_rec if Expression[addr].reduce_rec.kind_of? ::String
      l ||= addrstr if addr.kind_of? Expression and addr.externals.grep(::Symbol).empty?
    elsif not l = e.inv_export[e.ptr]
      l = @program.new_label(addrstr)
      e.add_export l, e.ptr
      @label_alias_cache = nil
      @old_prog_binding[l] = @prog_binding[l] = b + e.ptr
    elsif rewritepfx.find { |p| base != p and addrstr.sub(base, p) == l }
      newl = addrstr
      newl = @program.new_label(newl) unless @old_prog_binding[newl] and @old_prog_binding[newl] == @prog_binding[l]	# avoid _uuid when a -> b -> a
      rename_label l, newl
      l = newl
    end
    l
  end

  # returns a hash associating addr => list of labels at this addr
  def label_alias
    if not @label_alias_cache
      @label_alias_cache = {}
      @prog_binding.each { |k, v|
        (@label_alias_cache[v] ||= []) << k
      }
    end
    @label_alias_cache
  end

  # decodes instructions from an entrypoint, (tries to) follows code flow
  def disassemble(*entrypoints)
    nil while disassemble_mainiter(entrypoints)
    self
  end

  attr_accessor :entrypoints

  # do one operation relevant to disassembling
  # returns nil once done
  def disassemble_mainiter(entrypoints=[])
    @entrypoints ||= []
    if @addrs_todo.empty? and entrypoints.empty?
      post_disassemble
      puts 'disassembly finished' if $VERBOSE
      @callback_finished[] if callback_finished
      return false
    elsif @addrs_todo.empty?
      ep = entrypoints.shift
      l = auto_label_at(normalize(ep), 'entrypoint')
      puts "start disassemble from #{l} (#{entrypoints.length})" if $VERBOSE and not entrypoints.empty?
      @entrypoints << l
      @addrs_todo << [ep]
    else
      disassemble_step
    end
    true
  end

  def post_disassemble
    @decoded.each_value { |di|
      next if not di.kind_of? DecodedInstruction
      next if not di.opcode or not di.opcode.props[:saveip]
      if not di.block.to_subfuncret
        di.add_comment 'noreturn'
        # there is no need to re-loop on all :saveip as check_noret is transitive
        di.block.each_to_normal { |fa| check_noreturn_function(fa) }
      end
    }
    @function.each { |addr, f|
      next if not @decoded[addr]
      if not f.finalized
        f.finalized = true
puts "  finalize subfunc #{Expression[addr]}" if debug_backtrace
        @cpu.backtrace_update_function_binding(self, addr, f, f.return_address)
        if not f.return_address
          detect_function_thunk(addr)
        end
      end
      @comment[addr] ||= []
      bd = f.backtrace_binding.reject { |k, v| Expression[k] == Expression[v] or Expression[v] == Expression::Unknown }
      unk = f.backtrace_binding.map { |k, v| k if v == Expression::Unknown }.compact
      bd[unk.map { |u| Expression[u].to_s }.sort.join(',')] = Expression::Unknown if not unk.empty?
      @comment[addr] |= ["function binding: " + bd.map { |k, v| "#{k} -> #{v}" }.sort.join(', ')]
      @comment[addr] |= ["function ends at " + f.return_address.map { |ra| Expression[ra] }.join(', ')] if f.return_address
    }
  end

  # disassembles one block from addrs_todo
  # adds next addresses to handle to addrs_todo
  # if @function[:default] exists, jumps to unknows locations are interpreted as to @function[:default]
  def disassemble_step
    return if not todo = @addrs_todo.pop or @addrs_done.include? todo
    @addrs_done << todo if todo[1]

    # from_sfret is true if from is the address of a function call that returns to addr
    addr, from, from_subfuncret = todo

    return if from == Expression::Unknown

    puts "disassemble_step #{Expression[addr]} #{Expression[from] if from} #{from_subfuncret}  (/#{@addrs_todo.length})" if $DEBUG

    addr = normalize(addr)

    if from and from_subfuncret and di_at(from)
      @decoded[from].block.each_to_normal { |subfunc|
        subfunc = normalize(subfunc)
        next if not f = @function[subfunc] or f.finalized
        f.finalized = true
puts "  finalize subfunc #{Expression[subfunc]}" if debug_backtrace
        @cpu.backtrace_update_function_binding(self, subfunc, f, f.return_address)
        if not f.return_address
          detect_function_thunk(subfunc)
        end
      }
    end

    if di = @decoded[addr]
      if di.kind_of? DecodedInstruction
        split_block(di.block, di.address) if not di.block_head?	# this updates di.block
        di.block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
        bf = di.block
      elsif di == true
        bf = @function[addr]
      end
    elsif bf = @function[addr]
      detect_function_thunk_noreturn(from) if bf.noreturn
    elsif s = get_section_at(addr)
      block = InstructionBlock.new(normalize(addr), s[0])
      block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
      disassemble_block(block)
    elsif from and c_parser and name = Expression[addr].reduce_rec and name.kind_of? ::String and
        s = c_parser.toplevel.symbol[name] and s.type.untypedef.kind_of? C::Function
      bf = @function[addr] = @cpu.decode_c_function_prototype(@c_parser, s)
      detect_function_thunk_noreturn(from) if bf.noreturn
    elsif from
      if bf = @function[:default]
        puts "using default function for #{Expression[addr]} from #{Expression[from]}" if $DEBUG
        if name = Expression[addr].reduce_rec and name.kind_of? ::String
          @function[addr] = @function[:default].dup
        else
          addr = :default
        end
        if @decoded[from]
          @decoded[from].block.add_to addr
        end
      else
        puts "not disassembling unknown address #{Expression[addr]} from #{Expression[from]}" if $DEBUG
      end
      if from != :default
        add_xref(addr, Xref.new(:x, from))
        add_xref(Expression::Unknown, Xref.new(:x, from))
      end
    else
      puts "not disassembling unknown address #{Expression[addr]}" if $VERBOSE
    end

    if bf and from and from != :default
      if bf.kind_of? DecodedFunction
        bff = bf.get_backtracked_for(self, addr, from)
      else
        bff = bf.backtracked_for
      end
    end
    bff.each { |btt|
      next if btt.address
      if @decoded[from].kind_of? DecodedInstruction and @decoded[from].opcode.props[:saveip] and not from_subfuncret and not @function[addr]
        backtrace_check_found(btt.expr, @decoded[addr], btt.origin, btt.type, btt.len, btt.maxdepth, btt.detached)
      end
      next if backtrace_check_funcret(btt, addr, from)
      backtrace(btt.expr, from,
          :include_start => true, :from_subfuncret => from_subfuncret,
          :origin => btt.origin, :orig_expr => btt.orig_expr, :type => btt.type,
          :len => btt.len, :detached => btt.detached, :maxdepth => btt.maxdepth)
    } if bff
  end

  # splits an InstructionBlock, updates the blocks backtracked_for
  def split_block(block, address=nil)
    if not address	# invoked as split_block(0x401012)
      return if not @decoded[block].kind_of? DecodedInstruction
      block, address = @decoded[block].block, block
    end
    return block if address == block.address
    new_b = block.split address
    new_b.backtracked_for.dup.each { |btt|
      backtrace(btt.expr, btt.address,
          :only_upto => block.list.last.address,
          :include_start => !btt.exclude_instr, :from_subfuncret => btt.from_subfuncret,
          :origin => btt.origin, :orig_expr => btt.orig_expr, :type => btt.type, :len => btt.len,
          :detached => btt.detached, :maxdepth => btt.maxdepth)
    }
    new_b
  end

  # disassembles a new instruction block at block.address (must be normalized)
  def disassemble_block(block)
    raise if not block.list.empty?
    di_addr = block.address
    delay_slot = nil
    di = nil

    # try not to run for too long
    # loop usage: break if the block continues to the following instruction, else return
    @disassemble_maxblocklength.times {
      # check collision into a known block
      break if @decoded[di_addr]

      # check self-modifying code
      if @check_smc
        #(-7...di.bin_length).each { |off|	# uncomment to check for unaligned rewrites
        waddr = di_addr		#di_addr + off
        each_xref(waddr, :w) { |x|
          #next if off + x.len < 0
          puts "W: disasm: self-modifying code at #{Expression[waddr]}" if $VERBOSE
          @comment[di_addr] ||= []
          @comment[di_addr] |= ["overwritten by #{@decoded[x.origin]}"]
          @callback_selfmodifying[di_addr] if callback_selfmodifying
          return
        }
        #}
      end

      # decode instruction
      block.edata.ptr = di_addr - block.address + block.edata_ptr
      if not di = @cpu.decode_instruction(block.edata, di_addr)
        ed = block.edata
        puts "#{ed.ptr >= ed.length ? "end of section reached" : "unknown instruction #{ed.data[di_addr-block.address+block.edata_ptr, 4].to_s.unpack('H*')}"} at #{Expression[di_addr]}" if $VERBOSE
        return
      end

      @decoded[di_addr] = di
      block.add_di di
      puts di if $DEBUG

      di = @callback_newinstr[di] if callback_newinstr
      return if not di
      block = di.block

      di_addr = di.next_addr

      backtrace_xrefs_di_rw(di)

      if not di_addr or di.opcode.props[:stopexec] or not @program.get_xrefs_x(self, di).empty?
        # do not backtrace until delay slot is finished (eg MIPS: di is a
               #  ret and the delay slot holds stack fixup needed to calc func_binding)
        # XXX if the delay slot is also xref_x or :stopexec it is ignored
        delay_slot ||= [di, @cpu.delay_slot(di)]
      end

      if delay_slot
        di, delay = delay_slot
        if delay == 0 or not di_addr
          backtrace_xrefs_di_x(di)
          if di.opcode.props[:stopexec] or not di_addr; return
          else break
          end
        end
        delay_slot[1] = delay - 1
      end
    }

    ar = [di_addr]
    ar = @callback_newaddr[block.list.last.address, ar] || ar if callback_newaddr
    ar.each { |di_addr_| backtrace(di_addr_, di.address, :origin => di.address, :type => :x) }

    block
  end

  # retrieve the list of execution crossrefs due to the decodedinstruction
  # returns a list of symbolic expressions
  def get_xrefs_x(di)
    @program.get_xrefs_x(self, di)
  end

  # retrieve the list of data r/w crossrefs due to the decodedinstruction
  # returns a list of [type, symbolic expression, length]
  def get_xrefs_rw(di)
    @program.get_xrefs_rw(self, di)
  end

  # disassembles_fast from a list of entrypoints, also dasm subfunctions
  def disassemble_fast_deep(*entrypoints)
    @entrypoints ||= []
    @entrypoints |= entrypoints

    entrypoints.each { |ep| do_disassemble_fast_deep(normalize(ep)) }
  end

  def do_disassemble_fast_deep(ep)
    disassemble_fast(ep) { |fa, di|
      fa = normalize(fa)
      do_disassemble_fast_deep(fa)
      if di and ndi = di_at(fa)
        ndi.block.add_from_normal(di.address)
      end
    }
  end

  # disassembles fast from a list of entrypoints
  # see disassemble_fast_step
  def disassemble_fast(entrypoint, maxdepth=-1, &b)
    ep = [entrypoint]
    until ep.empty?
      disassemble_fast_step(ep, &b)
      maxdepth -= 1
      ep.delete_if { |a| not @decoded[normalize(a[0])] } if maxdepth == 0
    end
    check_noreturn_function(entrypoint)
  end

  # disassembles one block from the ary, see disassemble_fast_block
  def disassemble_fast_step(todo, &b)
    return if not x = todo.pop
    addr, from, from_subfuncret = x

    addr = normalize(addr)

    if di = @decoded[addr]
      if di.kind_of? DecodedInstruction
        split_block(di.block, di.address) if not di.block_head?
        di.block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
      end
    elsif s = get_section_at(addr)
      block = InstructionBlock.new(normalize(addr), s[0])
      block.add_from(from, from_subfuncret ? :subfuncret : :normal) if from and from != :default
      todo.concat disassemble_fast_block(block, &b)
    elsif name = Expression[addr].reduce_rec and name.kind_of? ::String and not @function[addr]
      if c_parser and s = c_parser.toplevel.symbol[name] and s.type.untypedef.kind_of? C::Function
        @function[addr] = @cpu.decode_c_function_prototype(@c_parser, s)
        detect_function_thunk_noreturn(from) if @function[addr].noreturn
      elsif @function[:default]
        @function[addr] = @function[:default].dup
      end
    end

    disassemble_fast_checkfunc(addr)
  end

  # check if an addr has an xref :x from a :saveip, if so mark as Function
  def disassemble_fast_checkfunc(addr)
    if @decoded[addr].kind_of? DecodedInstruction and not @function[addr]
      func = false
      each_xref(addr, :x) { |x_|
        func = true if odi = di_at(x_.origin) and odi.opcode.props[:saveip]
      }
      if func
        auto_label_at(addr, 'sub', 'loc', 'xref')
        # XXX use default_btbind_callback ?
        @function[addr] = DecodedFunction.new
        @function[addr].finalized = true
        detect_function_thunk(addr)
        puts "found new function #{get_label_at(addr)} at #{Expression[addr]}" if $VERBOSE
      end
    end
  end

  # disassembles fast a new instruction block at block.address (must be normalized)
  # does not recurse into subfunctions
  # assumes all :saveip returns, except those pointing to a subfunc with noreturn
  # yields subfunction addresses (targets of :saveip)
  # only backtrace for :x with maxdepth 1 (ie handles only basic push+ret)
  # returns a todo-style ary
  # assumes @addrs_todo is empty
  def disassemble_fast_block(block, &b)
    block = InstructionBlock.new(normalize(block), get_section_at(block)[0]) if not block.kind_of? InstructionBlock
    di_addr = block.address
    delay_slot = nil
    di = nil
    ret = []

    return ret if @decoded[di_addr]

    @disassemble_maxblocklength.times {
      break if @decoded[di_addr]

      # decode instruction
      block.edata.ptr = di_addr - block.address + block.edata_ptr
      if not di = @cpu.decode_instruction(block.edata, di_addr)
        return ret
      end

      @decoded[di_addr] = di
      block.add_di di
      puts di if $DEBUG

      di = @callback_newinstr[di] if callback_newinstr
      return ret if not di

      di_addr = di.next_addr

      if di.opcode.props[:stopexec] or di.opcode.props[:setip]
        if di.opcode.props[:setip]
          @addrs_todo = []
          @program.get_xrefs_x(self, di).each { |expr|
            backtrace(expr, di.address, :origin => di.address, :type => :x, :maxdepth => @backtrace_maxblocks_fast)
          }
        end
        if di.opcode.props[:saveip]
          @addrs_todo = []
          ret.concat disassemble_fast_block_subfunc(di, &b)
        else
          ret.concat @addrs_todo
          @addrs_todo = []
        end
        delay_slot ||= [di, @cpu.delay_slot(di)]
      end

      if delay_slot
        if delay_slot[1] <= 0
          return ret if delay_slot[0].opcode.props[:stopexec]
          break
        end
        delay_slot[1] -= 1
      end
    }

    di.block.add_to_normal(di_addr)
    ret << [di_addr, di.address]
  end

  # handles when disassemble_fast encounters a call to a subfunction
  def disassemble_fast_block_subfunc(di)
    funcs = di.block.to_normal.to_a
    do_ret = funcs.empty?
    ret = []
    na = di.next_addr + di.bin_length * @cpu.delay_slot(di)
    funcs.each { |fa|
      fa = normalize(fa)
      disassemble_fast_checkfunc(fa)
      yield fa, di if block_given?
      if f = @function[fa] and bf = f.get_backtracked_for(self, fa, di.address) and not bf.empty?
        # this includes retaddr unless f is noreturn
        bf.each { |btt|
          next if btt.type != :x
          bt = backtrace(btt.expr, di.address, :include_start => true, :origin => btt.origin, :maxdepth => [@backtrace_maxblocks_fast, 1].max)
          if btt.detached
            ret.concat bt	# callback argument
          elsif bt.find { |a| normalize(a) == na }
            do_ret = true
          end
        }
      elsif not f or not f.noreturn
        do_ret = true
      end
    }
    if do_ret
      di.block.add_to_subfuncret(na)
      ret << [na, di.address, true]
      di.block.add_to_normal :default if not di.block.to_normal and @function[:default]
    end
    ret
  end

  # trace whose xrefs this di is responsible of
  def backtrace_xrefs_di_rw(di)
    get_xrefs_rw(di).each { |type, ptr, len|
      backtrace(ptr, di.address, :origin => di.address, :type => type, :len => len).each { |xaddr|
        next if xaddr == Expression::Unknown
        if @check_smc and type == :w
          #len.times { |off|	# check unaligned ?
          waddr = xaddr	#+ off
          if wdi = di_at(waddr)
            puts "W: disasm: #{di} overwrites #{wdi}" if $VERBOSE
            wdi.add_comment "overwritten by #{di}"
          end
          #}
        end
      }
    }
  end

  # trace xrefs for execution
  def backtrace_xrefs_di_x(di)
    ar = @program.get_xrefs_x(self, di)
    ar = @callback_newaddr[di.address, ar] || ar if callback_newaddr
    ar.each { |expr| backtrace(expr, di.address, :origin => di.address, :type => :x) }
  end

  # checks if the function starting at funcaddr is an external function thunk (eg jmp [SomeExtFunc])
  # the argument must be the address of a decodedinstruction that is the first of a function,
  #  which must not have return_addresses
  # returns the new thunk name if it was changed
  def detect_function_thunk(funcaddr)
    # check thunk linearity (no conditionnal branch etc)
    addr = funcaddr
    count = 0
    while b = block_at(addr)
      count += 1
      return if count > 5 or b.list.length > 4
      if b.to_subfuncret and not b.to_subfuncret.empty?
        return if b.to_subfuncret.length != 1
        addr = normalize(b.to_subfuncret.first)
        return if not b.to_normal or b.to_normal.length != 1
        # check that the subfunction is simple (eg get_eip)
        return if not sf = @function[normalize(b.to_normal.first)]
        return if not btb = sf.backtrace_binding
        btb = btb.dup
        btb.delete_if { |k, v| Expression[k] == Expression[v] }
               return if btb.length > 2 or btb.values.include? Expression::Unknown
      else
        return if not bt = b.to_normal
        if bt.include? :default
          addr = :default
          break
        elsif bt.length != 1
          return
        end
        addr = normalize(bt.first)
      end
    end
    fname = Expression[addr].reduce_rec
    if funcaddr != addr and f = @function[funcaddr]
      # forward get_backtrace_binding to target
      f.backtrace_binding = { :thunk => addr }
      f.noreturn = true if @function[addr] and @function[addr].noreturn
    end
    return if not fname.kind_of? ::String
    l = auto_label_at(funcaddr, 'sub', 'loc')
    return if l[0, 4] != 'sub_'
    puts "found thunk for #{fname} at #{Expression[funcaddr]}" if $DEBUG
    rename_label(l, @program.new_label("thunk_#{fname}"))
  end

  # this is called when reaching a noreturn function call, with the call address
  # it is responsible for detecting the actual 'call' instruction leading to this
  # noreturn function, and eventually mark the call target as a thunk
  def detect_function_thunk_noreturn(addr)
    5.times {
      return if not di = di_at(addr)
      if di.opcode.props[:saveip] and not di.block.to_subfuncret
        if di.block.to_normal.to_a.length == 1
          taddr = normalize(di.block.to_normal.first)
          if di_at(taddr)
            @function[taddr] ||= DecodedFunction.new
            return detect_function_thunk(taddr)
          end
        end
        break
      else
        from = di.block.from_normal.to_a + di.block.from_subfuncret.to_a
        if from.length == 1
          addr = from.first
        else break
        end
      end
    }
  end

  # given an address, detect if it may be a noreturn fuction
  # it is if all its end blocks are calls to noreturn functions
  # if it is, create a @function[fa] with noreturn = true
  # should only be called with fa = target of a call
  def check_noreturn_function(fa)
    fb = function_blocks(fa, false, false)
    lasts = fb.keys.find_all { |k| fb[k] == [] }
    return if lasts.empty?
    if lasts.all? { |la|
      b = block_at(la)
      next if not di = b.list.last
      (di.opcode.props[:saveip] and b.to_normal.to_a.all? { |tfa|
        tf = function_at(tfa) and tf.noreturn
      }) or (di.opcode.props[:stopexec] and not di.opcode.props[:setip])
    }
      # yay
      @function[fa] ||= DecodedFunction.new
      @function[fa].noreturn = true
    end
  end


  # walks the backtrace tree from an address, passing along an object
  #
  # the steps are (1st = event, followed by hash keys)
  #
  # for each decoded instruction encountered:
  # :di       :di
  #
  # when backtracking to a block through a decodedfunction:
  # (yield for each of the block's subfunctions)
  # (the decodedinstruction responsible for the call will be yield next)
  # :func     :func, :funcaddr, :addr, :depth
  #
  # when jumping from one block to another (excluding :loop): # XXX include :loops ?
  # :up       :from, :to, :sfret
  #
  # when the backtrack has nothing to backtrack to (eg program entrypoint):
  # :end      :addr
  #
  # when the backtrack stops by taking too long to complete:
  # :maxdepth :addr
  #
  # when the backtrack stops for encountering the specified stop address:
  # :stopaddr :addr
  #
  # when rebacktracking a block already seen in the current branch:
  # (looptrace is an array of [obj, block end addr, from_subfuncret], from oldest to newest)
  # :loop     :looptrace
  #
  # when the address does not match a known instruction/function:
  # :unknown_addr :addr
  #
  # the block return value is used as follow for :di, :func, :up and :loop:
  # false => the backtrace stops for the branch
  # nil => the backtrace continues with the current object
  # anything else => the backtrace continues with this object
  #
  # method arguments:
  #  obj is the initial value of the object
  #  addr is the address where the backtrace starts
  #  include_start is a bool specifying if the backtrace should start at addr or just before
  #  from_subfuncret is a bool specifying if addr points to a decodedinstruction that calls a subfunction
  #  stopaddr is an [array of] address of instruction, the backtrace will stop just after executing it
  #  maxdepth is the maximum depth (in blocks) for each backtrace branch.
  #  (defaults to dasm.backtrace_maxblocks, which defaults do Dasm.backtrace_maxblocks)
  def backtrace_walk(obj, addr, include_start, from_subfuncret, stopaddr, maxdepth)
    start_addr = normalize(addr)
    stopaddr = [stopaddr] if stopaddr and not stopaddr.kind_of? ::Array

    # array of [obj, addr, from_subfuncret, loopdetect]
    # loopdetect is an array of [obj, addr, from_type] of each end of block encountered
    todo = []

    # array of [obj, blockaddr]
    # avoids rewalking the same value
    done = []

    # updates todo with the addresses to backtrace next
    walk_up = lambda { |w_obj, w_addr, w_loopdetect|
      if w_loopdetect.length > maxdepth
        yield :maxdepth, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
      elsif stopaddr and stopaddr.include?(w_addr)
        yield :stopaddr, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
      elsif w_di = @decoded[w_addr] and w_di != w_di.block.list.first and w_di.address != w_di.block.address
        prevdi = w_di.block.list[w_di.block.list.index(w_di)-1]
        todo << [w_obj, prevdi.address, :normal, w_loopdetect]
      elsif w_di
        next if done.include? [w_obj, w_addr]
        done << [w_obj, w_addr]
        hadsomething = false
        w_di.block.each_from { |f_addr, f_type|
          next if f_type == :indirect
          hadsomething = true
          o_f_addr = f_addr
          f_addr = @decoded[f_addr].block.list.last.address if @decoded[f_addr].kind_of? DecodedInstruction	# delay slot
          if l = w_loopdetect.find { |l_obj, l_addr, l_type| l_addr == f_addr and l_type == f_type }
            f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
            if f_obj and f_obj != w_obj	# should avoid infinite loops
              f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
            end
          else
            f_obj = yield(:up, w_obj, :from => w_addr, :to => f_addr, :sfret => f_type, :loopdetect => w_loopdetect, :real_to => o_f_addr)
          end
          next if f_obj == false
          f_obj ||= w_obj
          f_loopdetect ||= w_loopdetect
          # only count non-trivial paths in loopdetect (ignore linear links)
          add_detect = [[f_obj, f_addr, f_type]]
          add_detect = [] if @decoded[f_addr].kind_of? DecodedInstruction and tmp = @decoded[f_addr].block and
              ((w_di.block.from_subfuncret.to_a == [] and w_di.block.from_normal == [f_addr] and
               tmp.to_normal == [w_di.address] and tmp.to_subfuncret.to_a == []) or
              (w_di.block.from_subfuncret == [f_addr] and tmp.to_subfuncret == [w_di.address]))
          todo << [f_obj, f_addr, f_type, f_loopdetect + add_detect ]
        }
        yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if not hadsomething
      elsif @function[w_addr] and w_addr != :default and w_addr != Expression::Unknown
        next if done.include? [w_obj, w_addr]
        oldlen = todo.length
        each_xref(w_addr, :x) { |x|
          f_addr = x.origin
          o_f_addr = f_addr
          f_addr = @decoded[f_addr].block.list.last.address if @decoded[f_addr].kind_of? DecodedInstruction	# delay slot
          if l = w_loopdetect.find { |l_obj, l_addr, l_type| l_addr == w_addr }
            f_obj = yield(:loop, w_obj, :looptrace => w_loopdetect[w_loopdetect.index(l)..-1], :loopdetect => w_loopdetect)
            if f_obj and f_obj != w_obj
              f_loopdetect = w_loopdetect[0...w_loopdetect.index(l)]
            end
          else
            f_obj = yield(:up, w_obj, :from => w_addr, :to => f_addr, :sfret => :normal, :loopdetect => w_loopdetect, :real_to => o_f_addr)
          end
          next if f_obj == false
          f_obj ||= w_obj
          f_loopdetect ||= w_loopdetect
          todo << [f_obj, f_addr, :normal, f_loopdetect + [[f_obj, f_addr, :normal]] ]
        }
        yield :end, w_obj, :addr => w_addr, :loopdetect => w_loopdetect if todo.length == oldlen
      else
        yield :unknown_addr, w_obj, :addr => w_addr, :loopdetect => w_loopdetect
      end
    }

    if include_start
      todo << [obj, start_addr, from_subfuncret ? :subfuncret : :normal, []]
    else
      walk_up[obj, start_addr, []]
    end

    while not todo.empty?
      obj, addr, type, loopdetect = todo.pop
      di = @decoded[addr]
      if di and type == :subfuncret
        di.block.each_to_normal { |sf|
          next if not f = @function[normalize(sf)]
          s_obj = yield(:func, obj, :func => f, :funcaddr => sf, :addr => addr, :loopdetect => loopdetect)
          next if s_obj == false
          s_obj ||= obj
          if l = loopdetect.find { |l_obj, l_addr, l_type| addr == l_addr and l_type == :normal }
            l_obj = yield(:loop, s_obj, :looptrace => loopdetect[loopdetect.index(l)..-1], :loopdetect => loopdetect)
            if l_obj and l_obj != s_obj
              s_loopdetect = loopdetect[0...loopdetect.index(l)]
            end
            next if l_obj == false
            s_obj = l_obj if l_obj
          end
          s_loopdetect ||= loopdetect
          todo << [s_obj, addr, :normal, s_loopdetect + [[s_obj, addr, :normal]] ]
        }
      elsif di
        # XXX should interpolate index if di is not in block.list, but what if the addresses are not Comparable ?
        di.block.list[0..(di.block.list.index(di) || -1)].reverse_each { |di_|
          di = di_	# XXX not sure..
          if stopaddr and ea = di.next_addr and stopaddr.include?(ea)
            yield :stopaddr, obj, :addr => ea, :loopdetect => loopdetect
            break
          end
          ex_obj = obj
          obj = yield(:di, obj, :di => di, :loopdetect => loopdetect)
          break if obj == false
          obj ||= ex_obj
        }
        walk_up[obj, di.block.address, loopdetect] if obj
      elsif @function[addr] and addr != :default and addr != Expression::Unknown
        ex_obj = obj
        obj = yield(:func, obj, :func => @function[addr], :funcaddr => addr, :addr => addr, :loopdetect => loopdetect)
        next if obj == false
        obj ||= ex_obj
        walk_up[obj, addr, loopdetect]
      else
        yield :unknown_addr, obj, :addr => addr, :loopdetect => loopdetect
      end
    end
  end

  # holds a backtrace result until a snapshot_addr is encountered
  class StoppedExpr
    attr_accessor :exprs
    def initialize(e) @exprs = e end
  end


  attr_accessor :debug_backtrace

  # backtraces the value of an expression from start_addr
  # updates blocks backtracked_for if type is set
  # uses backtrace_walk
  # all values returned are from backtrace_check_found (which may generate xrefs, labels, addrs to dasm) unless :no_check is specified
  # options:
  #  :include_start => start backtracking including start_addr
  #  :from_subfuncret =>
  #  :origin => origin to set for xrefs when resolution is successful
  #  :orig_expr => initial expression
  #  :type => xref type (:r, :w, :x, :addr)  when :x, the results are added to #addrs_todo
  #  :len => xref len (for :r/:w)
  #  :snapshot_addr => addr (or array of) where the backtracker should stop
  #   if a snapshot_addr is given, values found are ignored if continuing the backtrace does not get to it (eg maxdepth/unk_addr/end)
  #  :maxdepth => maximum number of blocks to backtrace
  #  :detached => true if backtracking type :x and the result should not have from = origin set in @addrs_todo
  #  :max_complexity{_data} => maximum complexity of the expression before aborting its backtrace
  #  :log => Array, will be updated with the backtrace evolution
  #  :only_upto => backtrace only to update bt_for for current block & previous ending at only_upto
  #  :no_check => don't use backtrace_check_found (will not backtrace indirection static values)
  #  :terminals => array of symbols with constant value (stop backtracking if all symbols in the expr are terminals) (only supported with no_check)
  def backtrace(expr, start_addr, nargs={})
    include_start   = nargs.delete :include_start
    from_subfuncret = nargs.delete :from_subfuncret
    origin          = nargs.delete :origin
    origexpr        = nargs.delete :orig_expr
    type            = nargs.delete :type
    len             = nargs.delete :len
    snapshot_addr   = nargs.delete(:snapshot_addr) || nargs.delete(:stopaddr)
    maxdepth        = nargs.delete(:maxdepth) || @backtrace_maxblocks
    detached        = nargs.delete :detached
    max_complexity  = nargs.delete(:max_complexity) || @backtrace_maxcomplexity
    max_complexity_data = nargs.delete(:max_complexity) || @backtrace_maxcomplexity_data
    bt_log          = nargs.delete :log	# array to receive the ongoing backtrace info
    only_upto       = nargs.delete :only_upto
    no_check        = nargs.delete :no_check
    terminals       = nargs.delete(:terminals) || []
    raise ArgumentError, "invalid argument to backtrace #{nargs.keys.inspect}" if not nargs.empty?

    expr = Expression[expr]

    origexpr = expr if origin == start_addr

    start_addr = normalize(start_addr)
    di = @decoded[start_addr]

    if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if debug_backtrace
      return []
    end

    if type == :r or type == :w
      max_complexity = max_complexity_data
      maxdepth = @backtrace_maxblocks_data if backtrace_maxblocks_data and maxdepth > @backtrace_maxblocks_data
    end

    if vals = (no_check ? (!need_backtrace(expr, terminals) and [expr]) : backtrace_check_found(expr,
        di, origin, type, len, maxdepth, detached))
      # no need to update backtracked_for
      return vals
    elsif maxdepth <= 0
      return [Expression::Unknown]
    end

    # create initial backtracked_for
    if type and origin == start_addr and di
      btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-1)
      btt.address = di.address
      btt.exclude_instr = true if not include_start
      btt.from_subfuncret = true if from_subfuncret and include_start
      btt.detached = true if detached
      di.block.backtracked_for |= [btt]
    end

    @callback_prebacktrace[] if callback_prebacktrace

    # list of Expression/Integer
    result = []

puts "backtracking #{type} #{expr} from #{di || Expression[start_addr || 0]} for #{@decoded[origin]}" if debug_backtrace or $DEBUG
    bt_log << [:start, expr, start_addr] if bt_log
    backtrace_walk(expr, start_addr, include_start, from_subfuncret, snapshot_addr, maxdepth) { |ev, expr_, h|
      expr = expr_
      case ev
      when :unknown_addr, :maxdepth
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
        result |= [expr] if not snapshot_addr
        @addrs_todo << [expr, (detached ? nil : origin)] if not snapshot_addr and type == :x and origin
      when :end
        if not expr.kind_of? StoppedExpr
          oldexpr = expr
          expr = backtrace_emu_blockup(h[:addr], expr)
puts "  backtrace up #{Expression[h[:addr]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
          bt_log << [:up, expr, oldexpr, h[:addr],  :end] if bt_log and expr != oldexpr
          if expr != oldexpr and not snapshot_addr and vals = (no_check ?
              (!need_backtrace(expr, terminals) and [expr]) :
              backtrace_check_found(expr, nil, origin, type, len,
                maxdepth-h[:loopdetect].length, detached))
            result |= vals
            next
          end
        end
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
        if not snapshot_addr
          result |= [expr]

          btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-h[:loopdetect].length-1)
          btt.detached = true if detached
          @decoded[h[:addr]].block.backtracked_for |= [btt] if @decoded[h[:addr]]
          @function[h[:addr]].backtracked_for |= [btt] if @function[h[:addr]] and h[:addr] != :default
          @addrs_todo << [expr, (detached ? nil : origin)] if type == :x and origin
        end
      when :stopaddr
        if not expr.kind_of? StoppedExpr
          oldexpr = expr
          expr = backtrace_emu_blockup(h[:addr], expr)
puts "  backtrace up #{Expression[h[:addr]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
          bt_log << [:up, expr, oldexpr, h[:addr], :end] if bt_log and expr != oldexpr
        end
puts "  backtrace end #{ev} #{expr}" if debug_backtrace
        result |= ((expr.kind_of?(StoppedExpr)) ? expr.exprs : [expr])
      when :loop
        next false if expr.kind_of? StoppedExpr
        t = h[:looptrace]
        oldexpr = t[0][0]
        next false if expr == oldexpr		# unmodifying loop
puts "  bt loop at #{Expression[t[0][1]]}: #{oldexpr} => #{expr} (#{t.map { |z| Expression[z[1]] }.join(' <- ')})" if debug_backtrace
        false
      when :up
        next false if only_upto and h[:to] != only_upto
        next expr if expr.kind_of? StoppedExpr
        oldexpr = expr
        expr = backtrace_emu_blockup(h[:from], expr)
puts "  backtrace up #{Expression[h[:from]]}->#{Expression[h[:to]]}  #{oldexpr}#{" => #{expr}" if expr != oldexpr}" if debug_backtrace
        bt_log << [:up, expr, oldexpr, h[:from], h[:to]] if bt_log

        if expr != oldexpr and vals = (no_check ? (!need_backtrace(expr, terminals) and [expr]) :
            backtrace_check_found(expr, @decoded[h[:from]], origin, type, len,
              maxdepth-h[:loopdetect].length, detached))
          if snapshot_addr
            expr = StoppedExpr.new vals
            next expr
          else
            result |= vals
            bt_log << [:found, vals, h[:from]] if bt_log
            next false
          end
        end

        if origin and type
          # update backtracked_for
          update_btf = lambda { |btf, new_btt|
            # returns true if btf was modified
            if i = btf.index(new_btt)
              btf[i] = new_btt if btf[i].maxdepth < new_btt.maxdepth
            else
              btf << new_btt
            end
          }

          btt = BacktraceTrace.new(expr, origin, origexpr, type, len, maxdepth-h[:loopdetect].length-1)
          btt.detached = true if detached
          if x = di_at(h[:from])
            update_btf[x.block.backtracked_for, btt]
          end
          if x = @function[h[:from]] and h[:from] != :default
            update_btf[x.backtracked_for, btt]
          end
          if x = di_at(h[:to])
            btt = btt.dup
            btt.address = x.address
            btt.from_subfuncret = true if h[:sfret] == :subfuncret
            if backtrace_check_funcret(btt, h[:from], h[:real_to] || h[:to])
puts "   function returns to caller" if debug_backtrace
              next false
            end
            if not update_btf[x.block.backtracked_for, btt]
puts "   already backtraced" if debug_backtrace
              next false
            end
          end
        end
        expr
      when :di, :func
        next if expr.kind_of? StoppedExpr
        if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if debug_backtrace
          next false
        end

oldexpr = expr
        case ev
        when :di
          h[:addr] = h[:di].address
          expr = backtrace_emu_instr(h[:di], expr)
          bt_log << [ev, expr, oldexpr, h[:di], h[:addr]] if bt_log and expr != oldexpr
        when :func
          expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, origin, maxdepth-h[:loopdetect].length)
          if snapshot_addr and snapshot_addr == h[:funcaddr]
            # XXX recursiveness detection needs to be fixed						
puts "  backtrace: recursive function #{Expression[h[:funcaddr]]}" if debug_backtrace
            next false
          end
          bt_log << [ev, expr, oldexpr, h[:funcaddr], h[:addr]] if bt_log and expr != oldexpr
        end
puts "  backtrace #{h[:di] || Expression[h[:funcaddr]]}  #{oldexpr} => #{expr}" if debug_backtrace and expr != oldexpr
        if vals = (no_check ? (!need_backtrace(expr, terminals) and [expr]) : backtrace_check_found(expr,
            h[:di], origin, type, len, maxdepth-h[:loopdetect].length, detached))
          if snapshot_addr
            expr = StoppedExpr.new vals
          else
            result |= vals
            bt_log << [:found, vals, h[:addr]] if bt_log
            next false
          end
        elsif expr.complexity > max_complexity
puts "  backtrace aborting, expr too complex" if debug_backtrace
          next false
        end
        expr
      else raise ev.inspect
      end
    }

puts '  backtrace result: ' + result.map { |r| Expression[r] }.join(', ') if debug_backtrace

    result
  end

  # checks if the BacktraceTrace is a call to a known subfunction
  # returns true and updates self.addrs_todo
  def backtrace_check_funcret(btt, funcaddr, instraddr)
    if di = @decoded[instraddr] and @function[funcaddr] and btt.type == :x and
        not btt.from_subfuncret and
        @cpu.backtrace_is_function_return(btt.expr, @decoded[btt.origin]) and
        retaddr = backtrace_emu_instr(di, btt.expr) and
        not need_backtrace(retaddr)
puts "  backtrace addrs_todo << #{Expression[retaddr]} from #{di} (funcret)" if debug_backtrace
      di.block.add_to_subfuncret normalize(retaddr)
      if @decoded[funcaddr].kind_of? DecodedInstruction
        # check that all callers :saveip returns (eg recursive call that was resolved
        # before we found funcaddr was a function)
        @decoded[funcaddr].block.each_from_normal { |fm|
          if fdi = di_at(fm) and fdi.opcode.props[:saveip] and not fdi.block.to_subfuncret
            backtrace_check_funcret(btt, funcaddr, fm)
          end
        }
      end
      if not @function[funcaddr].finalized
        # the function is not fully disassembled: arrange for the retaddr to be
        #  disassembled only after the subfunction is finished
        # for that we walk the code from the call, mark each block start, and insert the sfret
        #  just before the 1st function block address in @addrs_todo (which is pop()ed by dasm_step)
        faddrlist = []
        todo = []
        di.block.each_to_normal { |t| todo << normalize(t) }
        while a = todo.pop
          next if faddrlist.include? a or not get_section_at(a)
          faddrlist << a
          if @decoded[a].kind_of? DecodedInstruction
            @decoded[a].block.each_to_samefunc(self) { |t| todo << normalize(t) }
          end
        end

        idx = @addrs_todo.index(@addrs_todo.find { |r, i, sfr| faddrlist.include? normalize(r) }) || -1
        @addrs_todo.insert(idx, [retaddr, instraddr, true])
      else
        @addrs_todo << [retaddr, instraddr, true]
      end
      true
    end
  end

  # applies one decodedinstruction to an expression
  def backtrace_emu_instr(di, expr)
    @cpu.backtrace_emu(di, expr)
  end

  # applies one subfunction to an expression
  def backtrace_emu_subfunc(func, funcaddr, calladdr, expr, origin, maxdepth)
    bind = func.get_backtrace_binding(self, funcaddr, calladdr, expr, origin, maxdepth)
    Expression[expr.bind(bind).reduce]
  end

  # applies a location binding
  def backtrace_emu_blockup(addr, expr)
    (ab = @address_binding[addr]) ? Expression[expr.bind(ab).reduce] : expr
  end

  # static resolution of indirections
  def resolve(expr)
    binding = Expression[expr].expr_indirections.inject(@old_prog_binding) { |binding_, ind|
      e, b = get_section_at(resolve(ind.target))
      return expr if not e
      binding_.merge ind => Expression[ e.decode_imm("u#{8*ind.len}".to_sym, @cpu.endianness) ]
    }
    Expression[expr].bind(binding).reduce
  end

  # returns true if the expression needs more backtrace
  # it checks for the presence of a symbol (not :unknown), which means it depends on some register value
  def need_backtrace(expr, terminals=[])
    return if expr.kind_of? ::Integer
    !(expr.externals.grep(::Symbol) - [:unknown] - terminals).empty?
  end

  # returns an array of expressions, or nil if expr needs more backtrace
  # it needs more backtrace if expr.externals include a Symbol != :unknown (symbol == register value)
  # if it need no more backtrace, expr's indirections are recursively resolved
  # xrefs are created, and di args are updated (immediate => label)
  # if type is :x, addrs_todo is updated, and if di starts a block, expr is checked to see if it may be a subfunction return value
  #
  # expr indirection are solved by first finding the value of the pointer, and then rebacktracking for write-type access
  # detached is true if type is :x and from should not be set in addrs_todo (indirect call flow, eg external function callback)
  # if the backtrace ends pre entrypoint, returns the value encoded in the raw binary
  # XXX global variable (modified by another function), exported data, multithreaded app..
  # TODO handle memory aliasing (mov ebx, eax ; write [ebx] ; read [eax])
  # TODO trace expr evolution through backtrace, to modify immediates to an expr involving label names
  # TODO mov [ptr], imm ; <...> ; jmp [ptr] => rename imm as loc_XX
  #  eg. mov eax, 42 ; add eax, 4 ; jmp eax  =>  mov eax, some_label-4
  def backtrace_check_found(expr, di, origin, type, len, maxdepth, detached)
    # only entrypoints or block starts called by a :saveip are checked for being a function
    # want to execute [esp] from a block start
    if type == :x and di and di == di.block.list.first and @cpu.backtrace_is_function_return(expr, @decoded[origin]) and (
      # which is an entrypoint..
      (not di.block.from_normal and not di.block.from_subfuncret) or
      # ..or called from a saveip
      (bool = false ; di.block.each_from_normal { |fn| bool = true if @decoded[fn] and @decoded[fn].opcode.props[:saveip] } ; bool))

      # now we can mark the current address a function start
      # the actual return address will be found later (we tell the caller to continue the backtrace)
      addr = di.address
      l = auto_label_at(addr, 'sub', 'loc', 'xref')
      if not f = @function[addr]
        f = @function[addr] = DecodedFunction.new
        puts "found new function #{l} at #{Expression[addr]}" if $VERBOSE
      end
      f.finalized = false

      if @decoded[origin]
        f.return_address ||= []
        f.return_address |= [origin]
        @decoded[origin].add_comment "endsub #{l}"
        # TODO add_xref (to update the comment on rename_label)
      end

      f.backtracked_for |= @decoded[addr].block.backtracked_for.find_all { |btt| not btt.address }
    end

    return if need_backtrace(expr)

puts "backtrace #{type} found #{expr} from #{di} orig #{@decoded[origin] || Expression[origin] if origin}" if debug_backtrace
    result = backtrace_value(expr, maxdepth)
    # keep the ori pointer in the results to emulate volatile memory (eg decompiler prefers this)
    result << expr if not type
    result.uniq!

    # create xrefs/labels
    result.each { |e|
      backtrace_found_result(e, di, type, origin, len, detached)
    } if type and origin

    result
  end

  # returns an array of expressions with Indirections resolved (recursive with backtrace_indirection)
  def backtrace_value(expr, maxdepth)
    # array of expression with all indirections resolved
    result = [Expression[expr.reduce]]

    # solve each indirection sequentially, clone expr for each value (aka cross-product)
    result.first.expr_indirections.uniq.each { |i|
      next_result = []
      backtrace_indirection(i, maxdepth).each { |rr|
        next_result |= result.map { |e| Expression[e.bind(i => rr).reduce] }
      }
      result = next_result
    }

    result.uniq
  end

  # returns the array of values pointed by the indirection at its invocation (ind.origin)
  # first resolves the pointer using backtrace_value, if it does not point in edata keep the original pointer
  # then backtraces from ind.origin until it finds an :w xref origin
  # if no :w access is found, returns the value encoded in the raw section data
  # TODO handle unaligned (partial?) writes
  def backtrace_indirection(ind, maxdepth)
    if not ind.origin
      puts "backtrace_ind: no origin for #{ind}" if $VERBOSE
      return [ind]
    end

    ret = []

    decode_imm = lambda { |addr, len|
      edata, foo = get_section_at(addr)
      if edata
        Expression[ edata.decode_imm("u#{8*len}".to_sym, @cpu.endianness) ]
      else
        Expression::Unknown
      end
    }

    # resolve pointers (they may include Indirections)
    backtrace_value(ind.target, maxdepth).each { |ptr|
      # find write xrefs to the ptr
      refs = []
      each_xref(ptr, :w) { |x|
        # XXX should be rebacktracked on new xref
        next if not @decoded[x.origin]
        refs |= [x.origin]
      } if ptr != Expression::Unknown

      if refs.empty?
        if get_section_at(ptr)
          # static data, newer written : return encoded value
          ret |= [decode_imm[ptr, ind.len]]
          next
        else
          # unknown pointer : backtrace the indirection, hope it solves itself
          initval = ind
        end
      else
        # wait until we find a write xref, then backtrace the written value
        initval = true
      end

      # wait until we arrive at an xref'ing instruction, then backtrace the written value
      backtrace_walk(initval, ind.origin, true, false, nil, maxdepth-1) { |ev, expr, h|
        case ev
        when :unknown_addr, :maxdepth, :stopaddr
puts "   backtrace_indirection for #{ind.target} failed: #{ev}" if debug_backtrace
          ret |= [Expression::Unknown]
        when :end
          if not refs.empty? and (expr == true or not need_backtrace(expr))
            if expr == true
              # found a path avoiding the :w xrefs, read the encoded initial value
              ret |= [decode_imm[ptr, ind.len]]
            else
              bd = expr.expr_indirections.inject({}) { |h_, i| h_.update i => decode_imm[i.target, i.len] }
              ret |= [Expression[expr.bind(bd).reduce]]
            end
          else
            # unknown pointer, backtrace did not resolve...
            ret |= [Expression::Unknown]
          end
        when :di
          di = h[:di]
          if expr == true
            next true if not refs.include? di.address
            # find the expression to backtrace: assume this is the :w xref from this di
            writes = get_xrefs_rw(di)
            writes = writes.find_all { |x_type, x_ptr, x_len| x_type == :w and x_len == ind.len }
            if writes.length != 1
              puts "backtrace_ind: incompatible xrefs to #{ptr} from #{di}" if $DEBUG
              ret |= [Expression::Unknown]
              next false
            end
            expr = Indirection.new(writes[0][1], ind.len, di.address)
          end
          expr = backtrace_emu_instr(di, expr)
          # may have new indirections... recall bt_value ?
          #if not need_backtrace(expr)
          if expr.expr_externals.all? { |e| @prog_binding[e] or @function[normalize(e)] } and expr.expr_indirections.empty?
            ret |= backtrace_value(expr, maxdepth-1-h[:loopdetect].length)
            false
          else
            expr
          end
        when :func
          next true if expr == true	# XXX
          expr = backtrace_emu_subfunc(h[:func], h[:funcaddr], h[:addr], expr, ind.origin, maxdepth-h[:loopdetect].length)
          #if not need_backtrace(expr)
          if expr.expr_externals.all? { |e| @prog_binding[e] or @function[normalize(e)] } and expr.expr_indirections.empty?
            ret |= backtrace_value(expr, maxdepth-1-h[:loopdetect].length)
            false
          else
            expr
          end
        end
      }
    }

    ret
  end

  # creates xrefs, updates addrs_todo, updates instr args
  def backtrace_found_result(expr, di, type, origin, len, detached)
    n = normalize(expr)
    fallthrough = true if type == :x and o = di_at(origin) and not o.opcode.props[:stopexec] and n == o.block.list.last.next_addr	# delay_slot
    add_xref(n, Xref.new(type, origin, len)) if origin != :default and origin != Expression::Unknown and not fallthrough
    unk = true if n == Expression::Unknown

    add_xref(n, Xref.new(:addr, di.address)) if di and di.address != origin and not unk
    base = { nil => 'loc', 1 => 'byte', 2 => 'word', 4 => 'dword', 8 => 'qword' }[len] || 'xref'
    base = 'sub' if @function[n]
    n = Expression[auto_label_at(n, base, 'xref') || n] if not fallthrough
    n = Expression[n]

    # update instr args
    # TODO trace expression evolution to allow handling of
    #  mov eax, 28 ; add eax, 4 ; jmp eax
    #  => mov eax, (loc_xx-4)
    if di and not unk # and di.address == origin
      @cpu.replace_instr_arg_immediate(di.instruction, expr, n)
    end
    if @decoded[origin] and not unk
       @cpu.backtrace_found_result(self, @decoded[origin], expr, type, len)
    end

    # add comment
    if type and @decoded[origin] # and not @decoded[origin].instruction.args.include? n
      @decoded[origin].add_comment "#{type}#{len}:#{n}" if not fallthrough
    end

    # check if target is a string
    if di and type == :r and (len == 1 or len == 2) and s = get_section_at(n)
      l = s[0].inv_export[s[0].ptr]
      case len
      when 1; str = s[0].read(32).unpack('C*')
      when 2; str = s[0].read(64).unpack('v*')
      end
      str = str.inject('') { |str_, c|
        case c
        when 0x20..0x7e, ?\n, ?\r, ?\t; str_ << c
        else break str_
        end
      }
      if str.length >= 4
        di.add_comment "#{'L' if len == 2}#{str.inspect}"
        str = 'a_' + str.downcase.delete('^a-z0-9')[0, 12]
        if str.length >= 8 and l[0, 5] == 'byte_'
          rename_label(l, @program.new_label(str))
        end
      end
    end

    # XXX all this should be done in  backtrace() { <here> }
    if type == :x and origin
      if detached
        o = @decoded[origin] ? origin : di ? di.address : nil	# lib function callback have origin == libfuncname, so we must find a block somewhere else
        origin = nil
        @decoded[o].block.add_to_indirect(normalize(n)) if @decoded[o] and not unk
      else
        @decoded[origin].block.add_to_normal(normalize(n)) if @decoded[origin] and not unk
      end
      @addrs_todo << [n, origin]
    end
  end

  def to_s
    a = ''
    dump { |l| a << l << "\n" }
    a
  end

  # dumps the source, optionnally including data
  # yields (defaults puts) each line
  def dump(dump_data=true, &b)
    b ||= lambda { |l| puts l }
    @sections.sort_by { |addr, edata| addr.kind_of?(::Integer) ? addr : 0 }.each { |addr, edata|
      addr = Expression[addr] if addr.kind_of? ::String
      blockoffs = @decoded.values.grep(DecodedInstruction).map { |di| Expression[di.block.address, :-, addr].reduce if di.block_head? }.grep(::Integer).sort.reject { |o| o < 0 or o >= edata.length }
      b[@program.dump_section_header(addr, edata)]
      if not dump_data and edata.length > 16*1024 and blockoffs.empty?
        b["// [#{edata.length} data bytes]"]
        next
      end
      unk_off = 0	# last off displayed
      # blocks.sort_by { |b| b.addr }.each { |b|
      while unk_off < edata.length
        if unk_off == blockoffs.first
          blockoffs.shift
          di = @decoded[addr+unk_off]
          if unk_off != di.block.edata_ptr
            b["\n// ------ overlap (#{unk_off-di.block.edata_ptr}) ------"]
          elsif di.block.from_normal.kind_of? ::Array
            b["\n"]
          end
          dump_block(di.block, &b)
          unk_off += [di.block.bin_length, 1].max
          unk_off = blockoffs.first if blockoffs.first and unk_off > blockoffs.first
        else
          next_off = blockoffs.first || edata.length
          if dump_data or next_off - unk_off < 16
            unk_off = dump_data(addr + unk_off, edata, unk_off, &b)
          else
            b["// [#{next_off - unk_off} data bytes]"]
            unk_off = next_off
          end
        end
      end
    }
  end

  # dumps a block of decoded instructions
  def dump_block(block, &b)
    b ||= lambda { |l| puts l }
    block = @decoded[block].block if @decoded[block]
    dump_block_header(block, &b)
    block.list.each { |di| b[di.show] }
  end

  # shows the xrefs/labels at block start
  def dump_block_header(block, &b)
    b ||= lambda { |l| puts l }
    xr = []
    each_xref(block.address) { |x|
      case x.type
      when :x; xr << Expression[x.origin]
      when :r, :w; xr << "#{x.type}#{x.len}:#{Expression[x.origin]}"
      end
    }
    if not xr.empty?
      b["\n// Xrefs: #{xr[0, 8].join(' ')}#{' ...' if xr.length > 8}"]
    end
    if block.edata.inv_export[block.edata_ptr]
      b["\n"] if xr.empty?
      label_alias[block.address].each { |name| b["#{name}:"] }
    end
    if c = @comment[block.address]
      c = c.join("\n") if c.kind_of? ::Array
      c.each_line { |l| b["// #{l}"] }
    end
  end

  # dumps data/labels, honours @xrefs.len if exists
  # dumps one line only
  # stops on end of edata/@decoded/@xref
  # returns the next offset to display
  # TODO array-style data access
  def dump_data(addr, edata, off, &b)
    b ||= lambda { |l| puts l }
    if l = edata.inv_export[off]
      l_list = label_alias[addr].to_a.sort
      l = l_list.pop || l
      l_list.each { |ll|
        b["#{ll}:"]
      }
      l = (l + ' ').ljust(16)
    else l = ''
    end
    elemlen = 1	# size of each element we dump (db by default)
    dumplen = -off % 16	# number of octets to dump
    dumplen = 16 if dumplen == 0
    cmt = []
    each_xref(addr) { |x|
      dumplen = elemlen = x.len if x.len == 2 or x.len == 4
      cmt << " #{x.type}#{x.len}:#{Expression[x.origin]}"
    }
    cmt = " ; @#{Expression[addr]}" + cmt.sort[0, 6].join
    if r = edata.reloc[off]
      dumplen = elemlen = r.type.to_s[1..-1].to_i/8
    end
    dataspec = { 1 => 'db ', 2 => 'dw ', 4 => 'dd ', 8 => 'dq ' }[elemlen]
    if not dataspec
      dataspec = 'db '
      elemlen = 1
    end
    l << dataspec

    # dup(?)
    if off >= edata.data.length
      dups = edata.virtsize - off
      @prog_binding.each_value { |a|
        tmp = Expression[a, :-, addr].reduce
        dups = tmp if tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
      }
      @xrefs.each_key { |a|
        tmp = Expression[a, :-, addr].reduce
        dups = tmp if tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
      }
      dups /= elemlen
      dups = 1 if dups < 1
      b[(l + "#{dups} dup(?)").ljust(48) << cmt]
      return off + dups*elemlen
    end

    vals = []
    edata.ptr = off
    dups = dumplen/elemlen
    elemsym = "u#{elemlen*8}".to_sym
    while edata.ptr < edata.data.length
      if vals.length > dups and vals.last != vals.first
        # we have a dup(), unread the last element which is different
        vals.pop
        addr = Expression[addr, :-, elemlen].reduce
        edata.ptr -= elemlen
        break
      end
      break if vals.length == dups and vals.uniq.length > 1
      vals << edata.decode_imm(elemsym, @cpu.endianness)
      addr += elemlen
      if i = (1-elemlen..0).find { |i_|
        t = addr + i_
        @xrefs[t] or @decoded[t] or edata.reloc[edata.ptr+i_] or edata.inv_export[edata.ptr+i_]
      }
        # i < 0
        edata.ptr += i
        addr += i
        break
      end
      break if edata.reloc[edata.ptr-elemlen]
    end

    # line of repeated value => dup()
    if vals.length > 8 and vals.uniq.length == 1
      b[(l << "#{vals.length} dup(#{Expression[vals.first]})").ljust(48) << cmt]
      return edata.ptr
    end

    # recognize strings
    vals = vals.inject([]) { |vals_, value|
      if (elemlen == 1 or elemlen == 2)
        case value
        when 0x20..0x7e, 0x0a, 0x0d
          if vals_.last.kind_of? ::String; vals_.last << value ; vals_
          else vals_ << value.chr
          end
        else vals_ << value
        end
      else vals_ << value
      end
    }

    vals.map! { |value|
      if value.kind_of? ::String
        if value.length > 2 # or value == vals.first or value == vals.last # if there is no xref, don't care
          value.inspect
        else
          value.unpack('C*').map { |c| Expression[c] }
        end
      else
        Expression[value]
      end
    }
    vals.flatten!

    b[(l << vals.join(', ')).ljust(48) << cmt]

    edata.ptr
  end

  def decompiler
    parse_c '' if not c_parser
    @decompiler ||= Decompiler.new(self)
  end
  def decompiler=(dc)
    @decompiler = dc
  end
  def decompile(*addr)
    decompiler.decompile(*addr)
  end
  def decompile_func(addr)
    decompiler.decompile_func(addr)
  end

  # allows us to be AutoExe.loaded
  def self.autoexe_load(f, &b)
    d = load(f, &b)
    d.program
  end
end
end

require 'metasm/disassemble_api'
