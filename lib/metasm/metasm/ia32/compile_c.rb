#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/parse'
require 'metasm/compile_c'

module Metasm
class Ia32
class CCompiler < C::Compiler
  # holds compiler state information for a function
  # registers are saved as register number (see Ia32::Reg)
  # TODO cache eflags ? or just z ? (may be defered to asm_optimize)
  class State
    # variable => offset from ebp (::Integer or CExpression)
    attr_accessor :offset
    # the current function
    attr_accessor :func
    # register => CExpression
    attr_accessor :cache
    # array of register values used in the function (to save/restore at prolog/epilog)
    attr_accessor :dirty
    # the array of register values currently not available
    attr_accessor :used
    # the array of args in use (reg/modrm/composite) the reg dependencies are in +used+
    attr_accessor :inuse
    # variable => register for current scope (variable never on the stack)
    # bound registers are also in +used+
    attr_accessor :bound
    # list of reg values that are not kept across function call
    attr_accessor :abi_flushregs_call
    # list of regs we can trash without restoring them
    attr_accessor :abi_trashregs

    # +used+ includes ebp if true
    # nil if ebp is not reserved for stack variable addressing
    # Reg if used
    attr_accessor :saved_ebp

    def initialize(func)
      @func = func
      @offset = {}
      @cache = {}
      @dirty = []
      @used = [4]	# esp is always in use
      @inuse = []
      @bound = {}
      @abi_flushregs_call = [0, 1, 2]		# eax, ecx, edx (r8 etc ?)
      @abi_trashregs = [0, 1, 2]
    end
  end

  # tracks 2 registers storing a value bigger than each
  class Composite
    attr_accessor :low, :high
    def initialize(low, high)
             @low, @high = low, high
    end
    def sz; 64 end
  end

  # some address
  class Address
    attr_accessor :modrm, :target
    def initialize(modrm, target=nil)
      @modrm, @target = modrm, target
    end
    def sz; @modrm.adsz end
    def to_s; "#<Address: #@modrm>" end
  end


  def initialize(*a)
    super(*a)
    @cpusz = @exeformat.cpu.size
    @regnummax = (@cpusz == 64 ? 15 : 7)
  end

  # shortcut to add an instruction to the source
  def instr(name, *args)
    # XXX parse_postfix ?
    @source << Instruction.new(@exeformat.cpu, name, args)
  end

  # returns an available register, tries to find one not in @state.cache
  # do not use with sz==8 (aliasing ah=>esp)
  # does not put it in @state.inuse
  # TODO multipass for reg cache optimization
  # TODO dynamic regval for later fixup (need a value to be in ecx for shl, etc)
  def findreg(sz = @cpusz)
    caching = @state.cache.keys.grep(Reg).map { |r| r.val }
    if not regval = ([*0..@regnummax] - @state.used - caching).first ||
                    ([*0..@regnummax] - @state.used).first
      raise 'need more registers! (or a better compiler?)'
    end
    getreg(regval, sz)
  end

  # returns a Reg from a regval, mark it as dirty, flush old cache dependencies
  def getreg(regval, sz=@cpusz)
    flushcachereg(regval)
    @state.dirty |= [regval]
    Reg.new(regval, sz)
  end

  # remove the cache keys that depends on the register
  def flushcachereg(regval)
    @state.cache.delete_if { |e, val|
      case e
      when Reg; e.val == regval
      when Address; e = e.modrm ; redo
      when ModRM; e.b && (e.b.val == regval) or e.i && (e.i.val == regval)
      when Composite; e.low.val == regval or e.high.val == regval
      end
    }
  end

  # removes elements from @state.inuse, free @state.used if unreferenced
  # must be the exact object present in inuse
  def unuse(*vals)
    vals.each { |val|
      val = val.modrm if val.kind_of? Address
      @state.inuse.delete val
    }
    # XXX cache exempt
    exempt = @state.bound.values.map { |r| r.kind_of? Composite ? [r.low.val, r.high.val] : r.val }.flatten
    exempt << 4
    exempt << 5 if @state.saved_ebp
    @state.used.delete_if { |regval|
      next if exempt.include? regval
      not @state.inuse.find { |val|
        case val
        when Reg; val.val == regval
        when ModRM; (val.b and val.b.val == regval) or (val.i and val.i.val == regval)
        when Composite; val.low.val == regval or val.high.val == regval
        else raise 'internal error - inuse ' + val.inspect
        end
      }
    }
  end

  # marks an arg as in use, returns the arg
  def inuse(v)
    case v
    when Reg; @state.used |= [v.val]
    when ModRM
      @state.used |= [v.i.val] if v.i
      @state.used |= [v.b.val] if v.b
    when Composite; @state.used |= [v.low.val, v.high.val]
    when Address; inuse v.modrm ; return v
    else return v
    end
    @state.inuse |= [v]
    v
  end

  # returns a variable storage (ModRM for stack/global, Reg/Composite for register-bound)
  def findvar(var)
    if ret = @state.bound[var]
      return ret
    end

    if ret = @state.cache.index(var)
      ret = ret.dup
      inuse ret
      return ret
    end

    sz = 8*sizeof(var) rescue nil	# extern char foo[];

    case off = @state.offset[var]
    when C::CExpression
      # stack, dynamic address
      # TODO
      # no need to update state.cache here, never recursive
      v = raise "find dynamic addr of #{var.name}"
    when ::Integer
      # stack
      # TODO -fomit-frame-pointer ( => state.cache dependant on stack_offset... )
      v = ModRM.new(@cpusz, sz, nil, nil, @state.saved_ebp, Expression[-off])
    when nil
      # global
      if @exeformat.cpu.generate_PIC
        if not reg = @state.cache.index('metasm_intern_geteip')
          @need_geteip_stub = true
          if @state.used.include? 6	# esi
            reg = findreg
          else
            reg = getreg 6
          end
          if reg.val != 0
            if @state.used.include? 0
              eax = Reg.new(0, @cpusz)
              instr 'mov', reg, eax
            else
              eax = getreg 0
            end
          end

          instr 'call', Expression['metasm_intern_geteip']

          if reg.val != 0
            if @state.used.include? 0
              instr 'xchg', eax, reg
            else
              instr 'mov', reg, eax
            end
          end

          @state.cache[reg] = 'metasm_intern_geteip'
        end
        v = ModRM.new(@cpusz, sz, nil, nil, reg, Expression[var.name, :-, 'metasm_intern_geteip'])
      else
        v = ModRM.new(@cpusz, sz, nil, nil, nil, Expression[var.name])
      end
    end

    case var.type
    when C::Array; inuse Address.new(v)
    else inuse v
    end
  end

  # resolves the Address to Reg/Expr (may encode an 'lea')
  def resolve_address(e)
    r = e.modrm
    unuse e
    if r.imm and not r.b and not r.i
      reg = r.imm
    elsif not r.imm and ((not r.b and r.s == 1) or not r.i)
      reg = r.b || r.i
    elsif reg = @state.cache.index(e)
      reg = reg.dup
    else
      reg = findreg
      r.sz = reg.sz
      instr 'lea', reg, r
    end
    inuse reg
    @state.cache[reg] = e
    reg
  end

  # copies the arg e to a volatile location (register/composite) if it is not already
  # unuses the old storage
  # may return a register bigger than the type size (eg __int8 are stored in full reg size)
  # use rsz only to force 32bits-return on a 16bits cpu
  def make_volatile(e, type, rsz=@cpusz)
    if e.kind_of? ModRM or @state.bound.index(e)
      if type.integral? or type.pointer?
        oldval = @state.cache[e]
        if type.integral? and type.name == :__int64 and @cpusz != 64
          e2l = inuse findreg(32)
          unuse e
          e2h = inuse findreg(32)
          el, eh = get_composite_parts e
          instr 'mov', e2l, el
          instr 'mov', e2h, eh
          e2 = inuse Composite.new(e2l, e2h)
          unuse e2l, e2h
        else
          unuse e
          n = type.integral? ? type.name : :ptr
          if (sz = typesize[n]*8) < @cpusz or sz < rsz or e.sz < rsz
            e2 = inuse findreg(rsz)
            op = ((type.specifier == :unsigned) ? 'movzx' : 'movsx')
            op = 'mov' if e.sz == e2.sz
          else
            e2 = inuse findreg(sz)
            op = 'mov'
          end
          instr op, e2, e
        end
        @state.cache[e2] = oldval if oldval and e.kind_of? ModRM
        e2
      elsif type.float?
        raise 'bad float static' + e.inspect if not e.kind_of? ModRM
        unuse e
        instr 'fld', e
        FpReg.new nil
      else raise
      end
    elsif e.kind_of? Address
      make_volatile resolve_address(e), type, rsz
    elsif e.kind_of? Expression
      if type.integral? or type.pointer?
        if type.integral? and type.name == :__int64 and @cpusz != 64
          e2 = inuse Composite.new(inuse(findreg(32)), findreg(32))
          instr 'mov', e2.low, Expression[e, :&, 0xffff_ffff]
          instr 'mov', e2.high, Expression[e, :>>, 32]
        else
          e2 = inuse findreg
          instr 'mov', e2, e
        end
        e2
      elsif type.float?
        case e.reduce
        when 0; instr 'fldz'
        when 1; instr 'fld1'
        else
          esp = Reg.new(4, @cpusz)
          instr 'push.i32', Expression[e, :>>, 32]
          instr 'push.i32', Expression[e, :&, 0xffff_ffff]
          instr 'fild', ModRM.new(@cpusz, 64, nil, nil, esp, nil)
          instr 'add', esp, 8
        end
        FpReg.new nil
      end
    else
      e
    end
  end

  # returns two args corresponding to the low and high 32bits of the 64bits composite arg
  def get_composite_parts(e)
    case e
    when ModRM
      el = e.dup
      el.sz = 32
      eh = el.dup
      eh.imm = Expression[eh.imm, :+, 4]
    when Expression
      el = Expression[e, :&, 0xffff_ffff]
      eh = Expression[e, :>>, 32]
    when Composite
      el = e.low
      eh = e.high
    when Reg
      el = e
      eh = findreg
    else raise
    end
    [el, eh]
  end

  # returns the instruction suffix for a comparison operator
  def getcc(op, type)
    case op
    when :'=='; 'z'
    when :'!='; 'nz'
    when :'<' ; 'b'
    when :'>' ; 'a'
    when :'<='; 'be'
    when :'>='; 'ae'
    else raise "bad comparison op #{op}"
    end.tr((type.specifier == :unsigned ? '' : 'ab'), 'gl')
  end

  # compiles a c expression, returns an Ia32 instruction argument
  def c_cexpr_inner(expr)
    case expr
    when ::Integer; Expression[expr]
    when C::Variable; findvar(expr)
    when C::CExpression
      if not expr.lexpr or not expr.rexpr
        inuse c_cexpr_inner_nol(expr)
      else
        inuse c_cexpr_inner_l(expr)
      end
    when C::Label; findvar(C::Variable.new(expr.name, C::Array.new(C::BaseType.new(:void), 1)))
    else puts "ia32/c_ce_i: unsupported #{expr}" if $VERBOSE
    end
  end

  # compile a CExpression with no lexpr
  def c_cexpr_inner_nol(expr)
    case expr.op
    when nil
      r = c_cexpr_inner(expr.rexpr)
      if (expr.rexpr.kind_of? C::CExpression or expr.rexpr.kind_of? C::Variable) and
          expr.type.kind_of? C::BaseType and expr.rexpr.type.kind_of? C::BaseType
        r = c_cexpr_inner_cast(expr, r)
      end
      r
    when :+
      c_cexpr_inner(expr.rexpr)
    when :-
      r = c_cexpr_inner(expr.rexpr)
      r = make_volatile(r, expr.type)
      if expr.type.integral? or expr.type.pointer?
        if r.kind_of? Composite
          instr 'neg', r.low
          instr 'adc', r.high, Expression[0]
          instr 'neg', r.high
        else
          instr 'neg', r
        end
      elsif expr.type.float?
        instr 'fchs'
      else raise
      end
      r
    when :'++', :'--'
      r = c_cexpr_inner(expr.rexpr)
      inc = true if expr.op == :'++'
      if expr.type.integral? or expr.type.pointer?
        if expr.type.integral? and expr.type.name == :__int64 and @cpusz != 64
          rl, rh = get_composite_parts r
          instr 'add', rl, Expression[inc ? 1 : -1]
          instr 'adc', rh, Expression[inc ? 0 : -1]
        else
          op = (inc ? 'inc' : 'dec')
          instr op, r
        end
      elsif expr.type.float?
        raise 'bad lvalue' if not r.kind_of? ModRM
        instr 'fld1'
        op = (inc ? 'faddp' : 'fsubp')
        instr op, r
        instr 'fstp', r
      end
      r
    when :&
      raise 'bad precompiler ' + expr.to_s if not expr.rexpr.kind_of? C::Variable
      @state.cache.each { |r_, c|
        return inuse(r_) if c.kind_of? Address and c.target == expr.rexpr
      }
      r = c_cexpr_inner(expr.rexpr)
      raise 'bad lvalue' if not r.kind_of? ModRM
      unuse r
      r = Address.new(r)
      inuse r
      r.target = expr.rexpr
      r
    when :*
      expr.rexpr.type.name = :ptr if expr.rexpr.kind_of? C::CExpression and expr.rexpr.type.kind_of? C::BaseType and typesize[expr.rexpr.type.name] == typesize[:ptr]	# hint to use Address
      e = c_cexpr_inner(expr.rexpr)
      sz = 8*sizeof(expr)
      case e
      when Address
        unuse e
        e = e.modrm.dup
        e.sz = sz
        inuse e
      when ModRM; e = make_volatile(e, expr.rexpr.type) if not expr.rexpr.type.float?
      end
      case e
      when Reg; unuse e ; e = inuse ModRM.new(@cpusz, sz, nil, nil, e, nil)
      when Expression; e = inuse ModRM.new(@cpusz, sz, nil, nil, nil, e)
      end
      e
    when :'!'
      r = c_cexpr_inner(expr.rexpr)
      r = make_volatile(r, expr.rexpr.type)
      if expr.rexpr.type.integral? or expr.type.pointer?
        if expr.type.integral? and expr.rexpr.type.name == :__int64 and @cpusz != 64
          raise # TODO
        end
        r = make_volatile(r, expr.rexpr.type)
        instr 'test', r, r
      elsif expr.rexpr.type.float?
        if @exeformat.cpu.opcode_list_byname['fucomip']
          instr 'fldz'
          instr 'fucomip'
        else
          raise # TODO
        end
        r = inuse findreg
      else raise 'bad comparison ' + expr.to_s
      end
      if @exeformat.cpu.opcode_list_byname['setz']
        instr 'setz', Reg.new(r.val, 8)
        instr 'and', r, Expression[1]
      else
        instr 'mov', r, Expression[1]
        label = new_label('setcc')
        instr 'jz', Expression[label]
        instr 'mov', r, Expression[0]
        @source << Label.new(label)
      end
      r
    else raise 'mmh ? ' + expr.to_s
    end
  end

  # compile a cast (BaseType to BaseType)
  def c_cexpr_inner_cast(expr, r)
    esp = Reg.new(4, @cpusz)
    if expr.type.float? and expr.rexpr.type.float?
      if expr.type.name != expr.rexpr.type.name and r.kind_of? ModRM
        instr 'fld', r
        unuse r
        r = FpReg.new nil
      end
    elsif expr.type.float? and expr.rexpr.type.integral?
      r = resolve_address r if r.kind_of? Address
      return make_volatile(r, expr.type) if r.kind_of? Expression
      unuse r
      if expr.rexpr.type.specifier == :unsigned and r.sz != 64
        instr 'push.i32', Expression[0]
      end
      case r
      when ModRM
        case expr.rexpr.type.name
        when :__int8, :__int16
          r = make_volatile(r, expr.rexpr.type, 32)
          instr 'push', r
        else
          if expr.rexpr.type.specifier != :unsigned
            instr 'fild', r
            return FpReg.new(nil)
          end
          if r.sz == 64
            get_composite_parts(r).reverse_each { |rp| instr 'push', rp }
          else
          instr 'push', r
        end
        end
      when Composite
        instr 'push', r.high
        instr 'push', r.low
      when Reg
        if r.sz == 16
          op = ((expr.rexpr.type.specifier == :unsigned) ? 'movzx' : 'movsx')
          rr = r.dup
          rr.sz = 32
          instr op, rr, r
          r = rr
        end
        instr 'push', r
      end
      m = ModRM.new(@cpusz, r.sz, nil, nil, esp, nil)
      instr 'fild', m
      instr 'add', esp, (expr.rexpr.type.specifier == :unsigned ? 8 : Expression[r.sz/8])
      if expr.rexpr.type.specifier == :unsigned and r.sz == 64
        label = new_label('unsign_float')
        if m.sz == 64 and @cpusz < 64
          foo, m = get_composite_parts m
        end
        m2 = m
        m2 = make_volatile(m, expr.rexpr.type) if m.kind_of? ModRM
        m2 = get_composite_parts(m2)[0] if m2.kind_of? Composite
        instr 'test', m2, m2
        instr 'jns', Expression[label]
        instr 'push.i32', Expression[0x7fff_ffff]
        instr 'push.i32', Expression[0xffff_ffff]
        instr 'fild', m
        instr 'add', esp, 8
        instr 'faddp', FpReg.new(1)
        instr 'fld1'
        instr 'faddp', FpReg.new(1)
        @source << Label.new(label)
      end
      r = FpReg.new nil
    elsif expr.type.integral? and expr.rexpr.type.float?
      r = make_volatile(r, expr.rexpr.type)	# => ST(0)

      if expr.type.name == :__int64
        instr 'sub', esp, Expression[8]
        instr 'fistp', ModRM.new(@cpusz, 64, nil, nil, esp, nil)
        if @cpusz == 64
          r = findreg
          instr 'pop', r
        else
          r = Composite.new(findreg(32), findreg(32))
          instr 'pop', r.low
          instr 'pop', r.high
        end
      else
        instr 'sub', esp, Expression[4]
        instr 'fistp', ModRM.new(@cpusz, 32, nil, nil, esp, nil)
        r = findreg(32)
        instr 'pop', r
        tto = typesize[expr.type.name]*8
        instr 'and', r, Expression[(1<<tto)-1] if r.sz > tto
      end
      inuse r
    elsif (expr.type.integral? or expr.type.pointer?) and (expr.rexpr.type.integral? or expr.rexpr.type.pointer?)
      tto   = typesize[expr.type.integral? ? expr.type.name : :ptr]*8
      tfrom = typesize[expr.rexpr.type.integral? ? expr.rexpr.type.name : :ptr]*8
      r = resolve_address r if r.kind_of? Address
      if r.kind_of? Expression
        r = make_volatile r, expr.type
      elsif tfrom > tto
        if tfrom == 64 and r.kind_of? Composite
          unuse r
          r = r.low
          inuse r
        end
        case r
        when ModRM
          unuse r
          r = r.dup
          r.sz = tto
          inuse r
        when Reg
          instr 'and', r, Expression[(1<<tto)-1] if r.sz > tto
        end
      elsif tto > tfrom
        if tto == 64 and @cpusz != 64
          high = findreg(32)
          unuse r
          if not r.kind_of? Reg or r.sz != 32
            inuse high
            low = findreg(32)
            unuse high
            op = (r.sz == 32 ? 'mov' : (expr.rexpr.type.specifier == :unsigned ? 'movzx' : 'movsx'))
            instr op, low, r
            r = low
          end
          r = inuse Composite.new(r, high)
          if expr.type.specifier == :unsigned
            instr 'xor', r.high, r.high
          else
            instr 'mov', r.high, r.low
            instr 'sar', r.high, Expression[31]
          end
        elsif not r.kind_of? Reg or r.sz != @cpusz
          unuse r
          reg = inuse findreg
          op = (r.sz == reg.sz ? 'mov' : (expr.rexpr.type.specifier == :unsigned ? 'movzx' : 'movsx'))
          instr op, reg, r
          r = reg
        end
      end
    end
    r
  end

  # compiles a CExpression, not arithmetic (assignment, comparison etc)
  def c_cexpr_inner_l(expr)
    case expr.op
    when :funcall
      c_cexpr_inner_funcall(expr)
    when :'+=', :'-=', :'*=', :'/=', :'%=', :'^=', :'&=', :'|=', :'<<=', :'>>='
      l = c_cexpr_inner(expr.lexpr)
      raise 'bad lvalue' if not l.kind_of? ModRM and not @state.bound.index(l)
      instr 'fld', l if expr.type.float?
      r = c_cexpr_inner(expr.rexpr)
      op = expr.op.to_s.chop.to_sym
      c_cexpr_inner_arith(l, op, r, expr.type)
      instr 'fstp', l if expr.type.float?
      l
    when :'+', :'-', :'*', :'/', :'%', :'^', :'&', :'|', :'<<', :'>>'
      # both sides are already cast to the same type by the precompiler
      # XXX expr.type.pointer?
      if expr.type.integral? and expr.type.name == :ptr and expr.lexpr.type.kind_of? C::BaseType and
        typesize[expr.lexpr.type.name] == typesize[:ptr]
        expr.lexpr.type.name = :ptr
      end
      l = c_cexpr_inner(expr.lexpr)
      l = make_volatile(l, expr.type) if not l.kind_of? Address
      if expr.type.integral? and expr.type.name == :ptr and l.kind_of? Reg
        unuse l
        l = Address.new ModRM.new(l.sz, @cpusz, nil, nil, l, nil)
        inuse l
      end
      if l.kind_of? Address and expr.type.integral?
        l.modrm.imm = nil if l.modrm.imm and not l.modrm.imm.op and l.modrm.imm.rexpr == 0
        if l.modrm.b and l.modrm.i and l.modrm.s == 1 and l.modrm.b.val == l.modrm.i.val
          unuse l.modrm.b if l.modrm.b != l.modrm.i
          l.modrm.b = nil
          l.modrm.s = 2
        end
        case expr.op
        when :+
          rexpr = expr.rexpr
          rexpr = rexpr.rexpr while rexpr.kind_of? C::CExpression and not rexpr.op and rexpr.type.integral? and
            rexpr.rexpr.kind_of? C::CExpression and rexpr.rexpr.type.integral? and
            typesize[rexpr.type.name] == typesize[rexpr.rexpr.type.name]
          if rexpr.kind_of? C::CExpression and rexpr.op == :* and rexpr.lexpr
            r1 = c_cexpr_inner(rexpr.lexpr)
            r2 = c_cexpr_inner(rexpr.rexpr)
            r1, r2 = r2, r1 if r1.kind_of? Expression
            if r2.kind_of? Expression and [1, 2, 4, 8].include?(rr2 = r2.reduce)
              case r1
              when ModRM, Address, Reg
                r1 = make_volatile(r1, rexpr.type) if not r1.kind_of? Reg
                if not l.modrm.i or (l.modrm.i.val == r1.val and l.modrm.s == 1 and rr2 == 1)
                  unuse l, r1, r2
                  l = Address.new(l.modrm.dup)
                  inuse l
                  l.modrm.i = r1
                  l.modrm.s = (l.modrm.s || 0) + rr2
                  return l
                end
              end
            end
            r = make_volatile(r1, rexpr.type)
            c_cexpr_inner_arith(r, :*, r2, rexpr.type)
          else
            r = c_cexpr_inner(rexpr)
          end
          r = resolve_address r if r.kind_of? Address
          r = make_volatile(r, rexpr.type) if r.kind_of? ModRM
          case r
          when Reg
            unuse l
            l = Address.new(l.modrm.dup)
            inuse l
            if l.modrm.b
              if not l.modrm.i or (l.modrm.i.val == r.val and l.modrm.s == 1)
                l.modrm.i = r
                l.modrm.s = (l.modrm.s || 0) + 1
                unuse r
                return l
              end
            else
              l.modrm.b = r
              unuse r
              return l
            end
          when Expression
            unuse l, r
            l = Address.new(l.modrm.dup)
            inuse l
            l.modrm.imm = Expression[l.modrm.imm, :+, r]
            return l
          end
        when :-
          r = c_cexpr_inner(expr.rexpr)
          if r.kind_of? Expression
            unuse l, r
            l = Address.new(l.modrm.dup)
            inuse l
            l.modrm.imm = Expression[l.modrm.imm, :-, r]
            return l
          end
        when :*
          r = c_cexpr_inner(expr.rexpr)
          if r.kind_of? Expression and [1, 2, 4, 8].includre?(rr = r.reduce)
            if l.modrm.b and not l.modrm.i
              if rr != 1
                l.modrm.i = l.modrm.b
                l.modrm.s = rr
                l.modrm.imm = Expression[l.modrm.imm, :*, rr] if l.modrm.imm
              end
              unuse r
              return l
            elsif l.modrm.i and not l.modrm.b and l.modrm.s*rr <= 8
              l.modrm.s *= rr
              l.modrm.imm = Expression[l.modrm.imm, :*, rr] if l.modrm.imm and rr != 1
              unuse r
              return l
            end
          end
        end
      end
      l = make_volatile(l, expr.type) if l.kind_of? Address
      r ||= c_cexpr_inner(expr.rexpr)
      c_cexpr_inner_arith(l, expr.op, r, expr.type)
      l
    when :'='
      r = c_cexpr_inner(expr.rexpr)
      l = c_cexpr_inner(expr.lexpr)
      raise 'bad lvalue ' + l.inspect if not l.kind_of? ModRM and not @state.bound.index(l)
      r = resolve_address r if r.kind_of? Address
      r = make_volatile(r, expr.type) if l.kind_of? ModRM and r.kind_of? ModRM
      unuse r
      if expr.type.integral? or expr.type.pointer?
        if expr.type.integral? and expr.type.name == :__int64 and @cpusz != 64
          ll, lh = get_composite_parts l
          rl, rh = get_composite_parts r
          instr 'mov', ll, rl
          instr 'mov', lh, rh
        elsif r.kind_of? Address
          m = r.modrm.dup
          m.sz = l.sz
          instr 'lea', l, m
        else
          if l.kind_of? ModRM and r.kind_of? Reg and l.sz != r.sz
            raise if l.sz > r.sz
            if l.sz == 8 and r.val >= 4
              reg = ([0, 1, 2, 3] - @state.used).first
              if not reg
                eax = Reg.new(0, r.sz)
                instr 'push', eax
                instr 'mov', eax, r
                instr 'mov', l, Reg.new(eax.val, 8)
                instr 'pop', eax
              else
                flushecachereg(reg)
                instr 'mov', Reg.new(reg, r.sz), r
                instr 'mov', l, Reg.new(reg, 8)
              end
            else
              instr 'mov', l, Reg.new(r.val, l.sz)
            end
          else
            instr 'mov', l, r
          end
        end
      elsif expr.type.float?
        r = make_volatile(r, expr.type) if r.kind_of? Expression
        instr 'fstp', l
      end
      l
    when :>, :<, :>=, :<=, :==, :'!='
      l = c_cexpr_inner(expr.lexpr)
      l = make_volatile(l, expr.type)
      r = c_cexpr_inner(expr.rexpr)
      unuse r
      if expr.lexpr.type.integral? or expr.lexpr.type.pointer?
        if expr.lexpr.type.integral? and expr.lexpr.type.name == :__int64 and @cpusz != 64
          raise # TODO
        end
        instr 'cmp', l, r
      elsif expr.lexpr.type.float?
        raise # TODO
        instr 'fucompp', l, r
        l = inuse findreg
      else raise 'bad comparison ' + expr.to_s
      end
      opcc = getcc(expr.op, expr.type)
      if @exeformat.cpu.opcode_list_byname['set'+opcc]
        instr 'set'+opcc, Reg.new(l.val, 8)
        instr 'and', l, 1
      else
        instr 'mov', l, Expression[1]
        label = new_label('setcc')
        instr 'j'+opcc, Expression[label]
        instr 'mov', l, Expression[0]
        @source << Label.new(label)
      end
      l
    else
      raise 'unhandled cexpr ' + expr.to_s
    end
  end

  # compiles a subroutine call
  def c_cexpr_inner_funcall(expr)
    # check if an obj has an attribute - check on obj and its type
    hasattr = lambda { |o, a| (o.kind_of?(C::Variable) and o.has_attribute(a)) or o.type.has_attribute(a) }
    hasattrv = lambda { |o, a| (o.kind_of?(C::Variable) and o.has_attribute_var(a)) or o.type.has_attribute_var(a) }

    fargs = expr.lexpr.type.pointer? ? expr.lexpr.type.pointed.args : expr.lexpr.type.args

    backup = []
    if hasattr[expr.lexpr, 'fastcall']
      regargs = [1, 2][0, expr.rexpr.length]
      regargs += [nil] * (expr.rexpr.length-2) if expr.rexpr.length > 2
    else
      regargs = fargs.map { |a| hasattrv[a, 'register'] }.map { |a| Reg.from_str(a).val if a }
    end
    @state.abi_flushregs_call.each { |reg|
      next if reg == 4
      next if reg == 5 and @state.saved_ebp
      if not @state.used.include? reg
        if not @state.abi_trashregs.include? reg
          # XXX should exclude other code compiled by us (we wont trash reg)
          @state.dirty |= [reg]
        end
        next
      end
      backup << reg
      unuse reg
      instr 'push', Reg.new(reg, [@cpusz, 32].max)
    }
    regargs_list = regargs.compact
    regargs_list.each { |reg|
      next if backup.include? reg
      @state.dirty |= [reg]
      next if not @state.used.include? reg
      backup << reg
      instr 'push', Reg.new(reg, [@cpusz, 32].max)
    }
    expr.rexpr.reverse_each { |arg|
      a = c_cexpr_inner(arg)
      a = resolve_address a if a.kind_of? Address
      unuse a
      if r = regargs.pop
        inuse r
        instr 'mov', Reg.new(r, 32), a
        next
      end
      case arg.type
      when C::Pointer
        instr 'push', a
      when C::BaseType
        case t = arg.type.name
        when :__int8
          a = make_volatile(a, arg.type) if a.kind_of? ModRM
          unuse a
          instr 'push', a
        when :__int16
          # XXX __int8 unuse, why not here
          if @cpusz != 16 and a.kind_of? Reg
            instr 'push', Reg.new(a.val, @cpusz)
          else
            a = make_volatile(a, arg.type)
            unuse a
            instr 'push', a
          end
        when :__int32
          instr 'push', a
        when :__int64
          case a
          when Composite
            instr 'push', a.high
            instr 'push', a.low
          when Reg
            instr 'push', a
          when ModRM
            if @cpusz == 64
              instr 'push', a
            else
              ml, mh = get_composite_parts a
              instr 'push', mh
              instr 'push', ml
            end
          when Expression
            instr 'push.i32', Expression[a, :>>, 32]
            instr 'push.i32', Expression[a, :&, 0xffff_ffff]
          end
        when :float, :double, :longdouble
          esp = Reg.new(4, @cpusz)
          case a
          when Expression
            # assume expr is integral
            a = load_fp_imm(a)
            unuse a
          when ModRM
            instr 'fld', a
          end
          instr 'sub', esp, typesize[t]
          instr 'fstp', ModRM.new(@cpusz, (t == :longdouble ? 80 : (t == :double ? 64 : 32)), nil, nil, esp, nil)
        end
      when C::Union
        raise 'want a modrm ! ' + a.inspect if not a.kind_of? ModRM
        al = typesize[:ptr]
        argsz = (sizeof(arg) + al - 1) / al * al
        while argsz > 0
          argsz -= al
          m = a.dup
          m.sz = 8*al
          m.imm = Expression[m.imm, :+, argsz]
          instr 'push', m
        end
      end
    }
    if expr.lexpr.kind_of? C::Variable and expr.lexpr.type.kind_of? C::Function
      instr 'call', Expression[expr.lexpr.name]
      if not hasattr[expr.lexpr, 'stdcall'] and not hasattr[expr.lexpr, 'fastcall']
        al = typesize[:ptr]
        argsz = expr.rexpr.zip(fargs).inject(0) { |sum, (a, af)|
          af && hasattrv[af, 'register'] ?  sum : sum + (sizeof(a) + al - 1) / al * al
        }
        instr 'add', Reg.new(4, @cpusz), Expression[argsz] if argsz > 0
      end
    else
      ptr = c_cexpr_inner(expr.lexpr)
      unuse ptr
      if ptr.kind_of? Address
        if ptr.target.kind_of? C::Variable and not @state.offset[ptr.target]
          # call an existing global function, maybe after casting to another ABI
          ptr = Expression[ptr.target.name]
        else
          ptr = make_volatile(ptr, expr.lexpr.type)
        end
      end
      instr 'call', ptr
      f = expr.lexpr
      f = f.rexpr while f.kind_of? C::CExpression and not f.op and f.rexpr.kind_of? C::Typed and f.type == f.rexpr.type
      if not hasattr[f, 'stdcall'] and not hasattr[f, 'fastcall']
        al = typesize[:ptr]
        argsz = expr.rexpr.zip(fargs).inject(0) { |sum, (a, af)|
          af && hasattrv[af, 'register'] ? sum : sum + (sizeof(a) + al - 1) / al * al
        }
        instr 'add', Reg.new(4, @cpusz), Expression[argsz] if argsz > 0
      end
    end
    @state.abi_flushregs_call.each { |reg| flushcachereg reg }
    if expr.type.float?
      retreg = FpReg.new(nil)
    elsif not expr.type.kind_of? C::BaseType or expr.type.name != :void
      if @state.used.include? 0
        retreg = inuse findreg
      else
        retreg = inuse getreg(0)
      end
      if expr.type.integral? and expr.type.name == :__int64 and @cpusz != 64
        retreg.sz = 32
        if @state.used.include? 2
          retreg = inuse Composite.new(retreg, findreg(32))
        else
          retreg = inuse Composite.new(retreg, getreg(2, 32))
        end
        unuse retreg.low
      end
    end
    regargs_list.each { |reg| unuse reg }
    backup.reverse_each { |reg|
      sz = [@cpusz, 32].max
      if    retreg.kind_of? Composite and reg == 0
        # XXX wtf ?  and what if retreg.low.val == 2 and it was saved too..
        instr 'pop', Reg.new(retreg.low.val, sz)
        instr 'xchg', Reg.new(reg, sz), Reg.new(retreg.low.val, sz)
      elsif retreg.kind_of? Composite and reg == 2
        # ..boom !
        instr 'pop', Reg.new(retreg.high.val, sz)
        instr 'xchg', Reg.new(reg, sz), Reg.new(retreg.high.val, sz)
      elsif retreg.kind_of? Reg and reg == 0
        instr 'pop', Reg.new(retreg.val, sz)
        instr 'xchg', Reg.new(reg, sz), Reg.new(retreg.val, sz)
      else
        instr 'pop', Reg.new(reg, sz)
      end
      inuse reg
    }
    retreg
  end

  # compiles/optimizes arithmetic operations
  def c_cexpr_inner_arith(l, op, r, type)
    # optimizes *2 -> <<1
    if r.kind_of? Expression and (rr = r.reduce).kind_of? ::Integer
      if type.integral?
        log2 = lambda { |v|
          # TODO lol
          i = 0
          i += 1 while (1 << i) < v
          i if (1 << i) == v
        }
        if (lr = log2[rr]).kind_of? ::Integer
          case op
          when :*; return c_cexpr_inner_arith(l, :<<, Expression[lr], type)
          when :/; return c_cexpr_inner_arith(l, :>>, Expression[lr], type)
          when :%; return c_cexpr_inner_arith(l, :&, Expression[rr-1], type)
          end
        else
          # TODO /r => *(r^(-1)), *3 => stuff with magic constants..
        end
      elsif type.float?
        case op
        when :<<; return c_cexpr_inner_arith(l, :*, Expression[1<<rr], type)
        when :>>; return c_cexpr_inner_arith(l, :/, Expression[1<<rr], type)
        end
      end
    end

    if type.float?
      c_cexpr_inner_arith_float(l, op, r, type)
    elsif type.integral? and type.name == :__int64 and @cpusz != 64
      c_cexpr_inner_arith_int64compose(l, op, r, type)
    else
      c_cexpr_inner_arith_int(l, op, r, type)
    end
  end

  # compiles a float arithmetic expression
  # l is ST(0)
  def c_cexpr_inner_arith_float(l, op, r, type)
    op = case op
    when :+; 'fadd'
    when :-; 'fsub'
    when :*; 'fmul'
    when :/; 'fdiv'
    else raise "unsupported FPU operation #{l} #{op} #{r}"
    end

    unuse r
    case r
    when FpReg; instr op+'p', FpReg.new(1)
    when ModRM; instr op, r
    end
  end

  # compile an integral arithmetic expression, reg-sized
  def c_cexpr_inner_arith_int(l, op, r, type)
    op = case op
    when :+; 'add'
    when :-; 'sub'
    when :&; 'and'
    when :|; 'or'
    when :^; 'xor'
    when :>>; type.specifier == :unsigned ? 'shr' : 'sar'
    when :<<; 'shl'
    when :*; 'mul'
    when :/; 'div'
    when :%; 'mod'
    end

    case op
    when 'add', 'sub', 'and', 'or', 'xor'
      r = make_volatile(r, type) if l.kind_of? ModRM and r.kind_of? ModRM
      unuse r
      instr op, l, r
    when 'shr', 'sar', 'shl'
      if r.kind_of? Expression
        instr op, l, r
      else
        # XXX bouh
        r = make_volatile(r, C::BaseType.new(:__int8, :unsigned))
        unuse r
        if r.val != 1
          ecx = Reg.new(1, 32)
          instr 'xchg', ecx, Reg.new(r.val, 32)
          l = Reg.new(r.val, l.sz) if l.kind_of? Reg and l.val == 1
          @state.used.delete r.val if not @state.used.include? 1
          inuse ecx
        end
        instr op, l, Reg.new(1, 8)
        instr 'xchg', ecx, Reg.new(r.val, 32) if r.val != 1
      end
    when 'mul'
      if l.kind_of? ModRM
        if r.kind_of? Expression
          ll = findreg
          instr 'imul', ll, l, r
        else
          ll = make_volatile(l, type)
          unuse ll
          instr 'imul', ll, r
        end
        instr 'mov', l, ll
      else
        instr 'imul', l, r
      end
      unuse r
    when 'div', 'mod'
      lv = l.val if l.kind_of? Reg
      eax = Reg.from_str 'eax'
      edx = Reg.from_str 'edx'
      if @state.used.include? eax.val and lv != eax.val
        instr 'push', eax
        saved_eax = true
      end
      if @state.used.include? edx.val and lv != edx.val
        instr 'push', edx
        saved_edx = true
      end

      instr 'mov', eax, l if lv != eax.val

      if r.kind_of? Expression
        instr 'push', r
        esp = Reg.from_str 'esp'
        r = ModRM.new(@cpusz, 32, nil, nil, esp, nil)
        need_pop = true
      end

      if type.specifier == :unsigned
        instr 'mov', edx, Expression[0]
        instr 'div', r
      else
        instr 'cdq'
        instr 'idiv', r
      end
      unuse r

      instr 'add', esp, 4 if need_pop

      if op == 'div'
        instr 'mov', l, eax if lv != eax.val
      else
        instr 'mov', l, edx if lv != edx.val
      end

      instr 'pop', edx if saved_edx
      instr 'pop', eax if saved_eax
    end
  end

  # compile an integral arithmetic 64-bits expression on a non-64 cpu
  def c_cexpr_inner_arith_int64compose(l, op, r, type)
    op = case op
    when :+; 'add'
    when :-; 'sub'
    when :&; 'and'
    when :|; 'or'
    when :^; 'xor'
    when :>>; type.specifier == :unsigned ? 'shr' : 'sar'
    when :<<; 'shl'
    when :*; 'mul'
    when :/; 'div'
    when :%; 'mod'
    end

    ll, lh = get_composite_parts l
    # 1ULL << 2 -> 2 is not ULL
    r = make_volatile(r, C::BaseType.new("__int#{r.sz}".to_sym)) if l.kind_of? ModRM and r.kind_of? ModRM
    rl, rh = get_composite_parts(r) if not r.kind_of? Reg

    case op
    when 'add', 'sub', 'and', 'or', 'xor'
      unuse r
      instr op, ll, rl
      op = {'add' => 'adc', 'sub' => 'sbb'}[op] || op
      instr op, lh, rh unless (op == 'or' or op == 'xor') and rh.kind_of?(Expression) and rh.reduce == 0
    when 'shl', 'shr', 'sar'
      rlc = r.reduce if r.kind_of? Expression
      opd = { 'shl' => 'shld', 'shr' => 'shrd', 'sar' => 'shrd' }[op]

      ll, lh = lh, ll if op != 'shl'	# OMGHAX
      llv = ll
      if llv.kind_of? ModRM
        llv = make_volatile(llv, C::BaseType.new(:__int32))
        inuse ll
      end

      if rlc.kind_of? Integer
        case rlc
        when 0
        when 1..31
          instr opd, llv, lh, Expression[rlc]
          instr op, ll, Expression[rlc]
        when 32..63
          instr 'mov', lh, llv
          if op == 'sar'
            instr 'sar', ll, Expression[31]
          else
            instr 'mov', ll, Expression[0]
          end
          instr op, lh, Expression[rlc-32] if rlc != 32
        else
          if op == 'sar'
            instr 'sar', ll, Expression[31]
            instr 'mov', lh, llv
          else
            instr 'mov', ll, Expression[0]
            instr 'mov', lh, Expression[0]
          end
        end
      else
        r = make_volatile(r, C::BaseType.new(:__int8, :unsigned))
        r = r.low if r.kind_of? Composite
        rl ||= r

        cl = Reg.new(1, 8)
        ecx = Reg.new(1, 32)
        if r.val != 1
          instr 'xchg', ecx, Reg.new(r.val, 32)
          lh  = Reg.new(r.val, lh.sz)  if lh.kind_of?(Reg)  and lh.val == 1
          ll  = Reg.new(r.val, ll.sz)  if ll.kind_of?(Reg)  and ll.val == 1
          llv = Reg.new(r.val, llv.sz) if llv.kind_of?(Reg) and llv.val == 1
          @state.used.delete r.val if not @state.used.include? 1
          inuse ecx
        end

        labelh = new_label('shldh')
        labeld = new_label('shldd')
        instr 'test', ecx, Expression[0x20]
        instr 'jnz', Expression[labelh]
        instr opd, llv, lh, cl
        instr op, ll, cl
        instr 'jmp', Expression[labeld]
        @source << Label.new(labelh)
        instr op, llv, cl
        instr 'mov', lh, llv
        if op == 'sar'
          instr 'sar', ll, Expression[31]
        else
          instr 'mov', ll, Expression[0]
        end
        @source << Label.new(labeld)

        instr 'xchg', ecx, Reg.new(r.val, 32) if r.val != 1
        unuse ecx
      unuse r
      end
    when 'mul'
      # high = (low1*high2) + (high1*low2) + (low1*low2).high
      t1 = findreg(32)
      t2 = findreg(32)
      unuse t1, t2, r
      instr 'mov',  t1, ll
      instr 'mov',  t2, rl
      instr 'imul', t1, rh
      instr 'imul', t2, lh
      instr 'add',  t1, t2

      raise # TODO push eax/edx, mul, pop
      instr 'mov',  eax, ll
      if rl.kind_of? Expression
        instr 'mov', t2, rl
        instr 'mul', t2
      else
        instr 'mul',  rl
      end
      instr 'add', t1, edx
      instr 'mov', lh, t1
      instr 'mov', ll, eax

    when 'div'
      raise # TODO
    when 'mod'
      raise # TODO
    end
  end

  def c_cexpr(expr)
    case expr.op
    when :+, :-, :*, :/, :&, :|, :^, :%, :[], nil, :'.', :'->',
      :>, :<, :<=, :>=, :==, :'!=', :'!'
      # skip no-ops
      c_cexpr(expr.lexpr) if expr.lexpr.kind_of? C::CExpression
      c_cexpr(expr.rexpr) if expr.rexpr.kind_of? C::CExpression
    else unuse c_cexpr_inner(expr)
    end
  end

  def c_block_exit(block)
    @state.cache.delete_if { |k, v|
      case v
      when C::Variable; block.symbol.index v
      when Address; block.symbol.index v.target
      end
    }
    block.symbol.each { |s|
      unuse @state.bound.delete(s)
    }
  end

  def c_decl(var)
    if var.type.kind_of? C::Array and
        var.type.length.kind_of? C::CExpression
      reg = c_cexpr_inner(var.type.length)
      unuse reg
      instr 'sub', Reg.new(4, @cpusz), reg
      # TODO
    end
  end

  def c_ifgoto(expr, target)
    case o = expr.op
    when :<, :>, :<=, :>=, :==, :'!='
      l = c_cexpr_inner(expr.lexpr)
      r = c_cexpr_inner(expr.rexpr)
      if l.kind_of? Expression
        o = { :< => :>, :> => :<, :>= => :<=, :<= => :>= }[o] || o
        l, r = r, l
      end
      r = make_volatile(r, expr.type) if r.kind_of? ModRM and l.kind_of? ModRM
      unuse l, r
      if expr.lexpr.type.integral?
        if expr.lexpr.type.name == :__int64 and @cpusz != 64
          raise # TODO
        end
        instr 'cmp', l, r
      elsif expr.lexpr.type.float?
        raise # TODO
        instr 'fcmpp', l, r
      else raise 'bad comparison ' + expr.to_s
      end
      op = 'j' + getcc(o, expr.lexpr.type)
      instr op, Expression[target]
    when :'!'
      r = c_cexpr_inner(expr.rexpr)
      r = make_volatile(r, expr.rexpr.type)
      unuse r
      instr 'test', r, r
      instr 'jz', Expression[target]
    else
      r = c_cexpr_inner(expr)
      r = make_volatile(r, expr.type)
      unuse r
      instr 'test', r, r
      instr 'jnz', Expression[target]
    end
  end

  def c_goto(target)
    instr 'jmp', Expression[target]
  end

  def c_label(name)
    @state.cache.clear
    @source << '' << Label.new(name)
  end

  def c_return(expr)
    return if not expr
    @state.cache.delete_if { |r, v| r.kind_of? Reg and r.val == 0 and expr != v }
    r = c_cexpr_inner(expr)
    r = make_volatile(r, expr.type)
    unuse r
    case r
    when Composite
      if r.low.val == 2
        instr 'xchg', r.low, r.high
        instr 'mov', Reg.new(0, 32), r.low if r.high.val != 0
      else
        instr 'mov', Reg.new(2, 32), r.high if r.high.val != 2
        instr 'mov', Reg.new(0, 32), r.low if r.low.val != 0
      end
    when Reg
    instr 'mov', Reg.new(0, r.sz), r if r.val != 0
    when FpReg
      instr 'fld', FpReg.new(r.val) if r.val and r.val != 0
    end
  end

  def c_asm(stmt)
    if stmt.output or stmt.input or stmt.clobber
      raise # TODO (handle %%0 => eax, gas, etc)
    else
      raise if @state.func.initializer.symbol.keys.find { |sym| stmt.body =~ /\b#{Regexp.escape(sym)}\b/ }	# gsub ebp+off ?
      @source << stmt.body
    end
  end

  def c_init_state(func)
    @state = State.new(func)
    # ET_DYN trashes ebx too
    # XXX hope we're not a Shellcode to be embedded in an ELF..
    @state.abi_flushregs_call << 3 if @exeformat and @exeformat.shortname == 'elf'

    c_reserve_stack(func.initializer)
    off = @state.offset.values.max.to_i	# where to store register args
    off = 0 if off < 0

    al = typesize[:ptr]
    argoff = 2*al
    fa = func.type.args.dup
    if func.has_attribute('fastcall')
      2.times {
        if a = fa.shift
          off = c_reserve_stack_var(a, off)
          @state.offset[a] = off
        end
      }
    end
    fa.each { |a|
      if a.has_attribute_var('register') or a.type.has_attribute_var('register')
        off = c_reserve_stack_var(a, off)
        @state.offset[a] = off
        next
      end
      @state.offset[a] = -argoff
      argoff = (argoff + sizeof(a) + al - 1) / al * al
    }
    if not @state.offset.values.grep(::Integer).empty?
      @state.saved_ebp = Reg.new(5, @cpusz)
      @state.used << 5
    end
  end

  def c_prolog
    localspc = @state.offset.values.grep(::Integer).max
    return if @state.func.has_attribute('naked')
    if localspc
      al = typesize[:ptr]
      localspc = (localspc + al - 1) / al * al
      ebp = @state.saved_ebp
      esp = Reg.new(4, ebp.sz)
      instr 'push', ebp
      instr 'mov', ebp, esp
      instr 'sub', esp, Expression[localspc] if localspc > 0

      if @state.func.has_attribute('fastcall')
        if a0 = @state.func.type.args[0]
          instr 'mov', findvar(a0), Reg.new(1, 32)
        end
        if a1 = @state.func.type.args[1]
          instr 'mov', findvar(a1), Reg.new(2, 32)
        end
      else
        @state.func.type.args.each { |a|
          if r = (a.has_attribute_var('register') or a.type.has_attribute_var('register'))
            # XXX if r == ebp, then prepend_prolog mov [esp-off], ebp...
            # XXX this would break when calling anyway (mov ebp, 42; <stuff with &var_42>; call func)
            instr 'mov', findvar(a), Reg.from_str(r)
          end
        }
      end
    end
    @state.dirty -= @state.abi_trashregs	# XXX ABI
    @state.dirty.each { |reg|
      instr 'push', Reg.new(reg, @cpusz)
    }
  end

  def c_epilog
    return if @state.func.attributes.to_a.include? 'naked'
    # TODO revert dynamic array alloc
    @state.dirty.reverse_each { |reg|
      instr 'pop', Reg.new(reg, @cpusz)
    }
    if ebp = @state.saved_ebp
      instr 'mov', Reg.new(4, ebp.sz), ebp
      instr 'pop', ebp
    end
    f = @state.func
    if f.has_attribute('stdcall') or f.has_attribute('fastcall')
    al = typesize[:ptr]
      fa = f.type.args.dup
      2.times { fa.shift } if f.has_attribute('fastcall')
      argsz = fa.inject(0) { |sum, a|
        (a.has_attribute_var('register') or a.type.has_attribute_var('register')) ? sum : sum + (sizeof(a) + al - 1) / al * al
      }
      if argsz > 0
      instr 'ret', Expression[argsz]
    else
      instr 'ret'
    end
    else
      instr 'ret'
    end
  end

  # adds the metasm_intern_geteip function, which returns its own address in eax (used for PIC addressing)
  def c_program_epilog
    if defined? @need_geteip_stub and @need_geteip_stub
      return if new_label('metasm_intern_geteip') != 'metasm_intern_geteip'	# already defined elsewhere

      eax = Reg.new(0, @cpusz)
      label = new_label('geteip')

      @source << Label.new('metasm_intern_geteip')
      instr 'call', Expression[label]
      @source << Label.new(label)
      instr 'pop', eax
      instr 'add', eax, Expression['metasm_intern_geteip', :-, label]
      instr 'ret'
    end
#File.open('m-dbg-precomp.c', 'w') { |fd| fd.puts @parser }
#File.open('m-dbg-src.asm', 'w') { |fd| fd.puts @source }
  end

  def check_reserved_name(var)
    Reg.s_to_i[var.name]
  end
end

  def new_ccompiler(parser, exe=ExeFormat.new)
    exe.cpu = self if not exe.instance_variable_get("@cpu")
    CCompiler.new(parser, exe)
  end
end
end
