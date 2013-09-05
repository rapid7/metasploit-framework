#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/parse'
require 'metasm/compile_c'

module Metasm
class X86_64
class CCompiler < C::Compiler
  # holds compiler state information for a function
  # registers are saved as register number (see Reg)
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
    # the array of args in use (reg/modrm) the reg dependencies are in +used+
    attr_accessor :inuse
    # variable => register for current scope (variable never on the stack)
    # bound registers are also in +used+
    attr_accessor :bound
    # list of reg values that are used as func args in current ABI
    attr_accessor :regargs
    # stack space reserved for subfunction in ABI
    attr_accessor :args_space
    # list of reg values that are not kept across function call
    attr_accessor :abi_flushregs_call
    # list of regs we can trash without restoring them
    attr_accessor :abi_trashregs

    # +used+ includes ebp if true
    # nil if ebp is not reserved for stack variable addressing
    # Reg if used
    attr_accessor :saved_rbp

    def initialize(func)
      @func = func
      @offset = {}
      @cache = {}
      @dirty = []
      @used = [4]	# rsp is always in use
      @inuse = []
      @bound = {}
      @regargs = []
      @args_space = 0
      @abi_flushregs_call = [0, 1, 2, 6, 7, 8, 9, 10, 11]
      @abi_trashregs = @abi_flushregs_call.dup
    end
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
    @cpusz = 64
    @regnummax = 15
  end

  # shortcut to add an instruction to the source
  def instr(name, *args)
    # XXX parse_postfix ?
    @source << Instruction.new(@exeformat.cpu, name, args)
  end

  # returns an available register, tries to find one not in @state.cache
  # do not use with sz==8 (aliasing ah=>esp)
  # does not put it in @state.inuse
  def findreg(sz = @cpusz)
    caching = @state.cache.keys.grep(Reg).map { |r| r.val }
    if not regval = (@state.abi_trashregs - @state.used - caching).first ||
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
    exempt = @state.bound.values.map { |r| r.val }
    exempt << 4
    exempt << 5 if @state.saved_rbp
    @state.used.delete_if { |regval|
      next if exempt.include? regval
      not @state.inuse.find { |val|
        case val
        when Reg; val.val == regval
        when ModRM; (val.b and val.b.val == regval) or (val.i and val.i.val == regval)
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
      v = ModRM.new(@cpusz, sz, nil, nil, @state.saved_rbp, Expression[-off])
    when nil
      # global
      if @exeformat.cpu.generate_PIC
        v = ModRM.new(@cpusz, sz, nil, nil, Reg.from_str('rip'), Expression[var.name, :-, '$_'])
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
  def make_volatile(e, type, rsz=@cpusz)
    if e.kind_of? ModRM or @state.bound.index(e)
      if type.integral? or type.pointer?
        oldval = @state.cache[e]
        unuse e
        sz = typesize[type.pointer? ? :ptr : type.name]*8
        if sz < @cpusz or sz < rsz or e.sz < rsz
          e2 = inuse findreg(rsz)
          op = ((type.specifier == :unsigned) ? 'movzx' : 'movsx')
          op = 'mov' if e.sz == e2.sz
          if e2.sz == 64 and e.sz == 32
            if op == 'movsx'
              instr 'movsxd', e2, e
        else
              instr 'mov', Reg.new(e2.val, 32), e
        end
          else
        instr op, e2, e
          end
        else
          e2 = inuse findreg(sz)
          instr 'mov', e2, e
        end
        @state.cache[e2] = oldval if oldval and e.kind_of? ModRM
        e2
      elsif type.float?
        raise 'float unhandled'
      else raise
      end
    elsif e.kind_of? Address
      make_volatile resolve_address(e), type, rsz
    elsif e.kind_of? Expression
      if type.integral? or type.pointer?
        e2 = inuse findreg
        instr 'mov', e2, e
        e2
      elsif type.float?
        raise 'float unhandled'
      end
    else
      e
    end
  end

  # takes an argument, if the argument is an integer that does not fit in an i32, moves it to a temp reg
  # the reg is unused, so use this only right when generating the offending instr (eg cmp, add..)
  def i_to_i32(v)
    if v.kind_of? Expression and i = v.reduce and i.kind_of?(Integer)
      i &= 0xffff_ffff_ffff_ffff
      if i <= 0x7fff_ffff
      elsif i >= (1<<64)-0x8000_0000
        v = Expression[Expression.make_signed(i, 64)]
      else
        v = make_volatile(v)
        unuse v
      end
    end
    v
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

  # compiles a c expression, returns an X64 instruction argument
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
    else puts "c_ce_i: unsupported #{expr}" if $VERBOSE
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
        instr 'neg', r
      elsif expr.type.float?
        raise 'float unhandled'
      else raise
      end
      r
    when :'++', :'--'
      r = c_cexpr_inner(expr.rexpr)
      inc = true if expr.op == :'++'
      if expr.type.integral? or expr.type.pointer?
        op = (inc ? 'inc' : 'dec')
        instr op, r
      elsif expr.type.float?
        raise 'float unhandled'
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
      when ModRM; e = make_volatile(e, expr.rexpr.type)
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
        r = make_volatile(r, expr.rexpr.type)
        instr 'test', r, r
      elsif expr.rexpr.type.float?
        raise 'float unhandled'
      else raise 'bad comparison ' + expr.to_s
      end
      instr 'setz', Reg.new(r.val, 8)
      instr 'and', r, Expression[1]
      r
    else raise 'mmh ? ' + expr.to_s
    end
  end

  # compile a cast (BaseType to BaseType)
  def c_cexpr_inner_cast(expr, r)
    if expr.type.float? or expr.rexpr.type.float?
      raise 'float unhandled'
    elsif (expr.type.integral? or expr.type.pointer?) and (expr.rexpr.type.integral? or expr.rexpr.type.pointer?)
      tto   = typesize[expr.type.pointer? ? :ptr : expr.type.name]*8
      tfrom = typesize[expr.rexpr.type.pointer? ? :ptr : expr.rexpr.type.name]*8
      r = resolve_address r if r.kind_of? Address
      if r.kind_of? Expression
        r = make_volatile r, expr.type
      elsif tfrom > tto
        case r
        when ModRM
          unuse r
          r = r.dup
          r.sz = tto
          inuse r
        when Reg
          if r.sz == 64 and tto == 32
            instr 'mov', Reg.new(r.val, tto), Reg.new(r.val, tto)
          else
            instr 'and', r, Expression[(1<<tto)-1] if r.sz > tto
          end
        end
      elsif tto > tfrom
        if not r.kind_of? Reg or r.sz != @cpusz
          unuse r
          reg = inuse findreg
          op = (r.sz == reg.sz ? 'mov' : (expr.rexpr.type.specifier == :unsigned ? 'movzx' : 'movsx'))
          if reg.sz == 64 and r.sz == 32
            if op == 'movsx'
              instr 'movsxd', reg, r
            else
              instr 'mov', Reg.new(reg.val, 32), r
            end
          else
          instr op, reg, r
          end
          r = reg
        end
      end
    else raise
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
      r = c_cexpr_inner(expr.rexpr)
      op = expr.op.to_s.chop.to_sym
      c_cexpr_inner_arith(l, op, r, expr.type)
      l
    when :'+', :'-', :'*', :'/', :'%', :'^', :'&', :'|', :'<<', :'>>'
      # both sides are already cast to the same type by the precompiler
      # XXX fptrs are not #integral? ...
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
        if r.kind_of? Address
          m = r.modrm.dup
          m.sz = l.sz
          instr 'lea', l, m
        else
          if l.kind_of? ModRM and r.kind_of? Reg and l.sz != r.sz
            raise if l.sz > r.sz
            if l.sz == 8 and r.val >= 4
              reg = ([0, 1, 2, 3] - @state.used).first
              if not reg
                rax = Reg.new(0, r.sz)
                instr 'push', rax
                instr 'mov', rax, r
                instr 'mov', l, Reg.new(rax.val, 8)
                instr 'pop', rax
              else
                flushcachereg(reg)
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
        raise 'float unhandled'
      end
      l
    when :>, :<, :>=, :<=, :==, :'!='
      l = c_cexpr_inner(expr.lexpr)
      l = make_volatile(l, expr.type)
      r = c_cexpr_inner(expr.rexpr)
      unuse r
      if expr.lexpr.type.integral? or expr.lexpr.type.pointer?
        instr 'cmp', l, i_to_i32(r)
      elsif expr.lexpr.type.float?
        raise 'float unhandled'
      else raise 'bad comparison ' + expr.to_s
      end
      opcc = getcc(expr.op, expr.type)
      instr 'set'+opcc, Reg.new(l.val, 8)
      instr 'and', l, 1
      l
    else
      raise 'unhandled cexpr ' + expr.to_s
    end
  end

  # compiles a subroutine call
  def c_cexpr_inner_funcall(expr)
    backup = []
    rax = Reg.new(0, 64)

    ft = expr.lexpr.type
    ft = ft.pointed if ft.pointer?
    ft = nil if not ft.kind_of? C::Function

    arglist = expr.rexpr.dup
    regargsmask = @state.regargs.dup
    if ft
      ft.args.each_with_index { |a, i|
        if rn = a.has_attribute_var('register')
          regargsmask.insert(i, Reg.from_str(rn).val)
    end
      }
    end
    regargsmask = regargsmask[0, expr.rexpr.length]

    (@state.abi_flushregs_call | regargsmask.compact.uniq).each { |reg|
      next if reg == 4
      next if reg == 5 and @state.saved_rbp
      if not @state.used.include? reg
        if not @state.abi_trashregs.include? reg
          @state.dirty |= [reg]
        end
        next
      end
      backup << reg
      instr 'push', Reg.new(reg, 64)
      @state.used.delete reg
    }

    stackargs = expr.rexpr.zip(regargsmask).map { |a, r| a if not r }.compact

    # preserve 16byte stack align under windows
    stackalign = true if (stackargs + backup).length & 1 == 1
    instr 'push', rax if stackalign

    stackargs.reverse_each { |arg|
      raise 'arg unhandled' if not arg.type.integral? or arg.type.pointer?
      a = c_cexpr_inner(arg)
      a = resolve_address a if a.kind_of? Address
      a = make_volatile(a, arg.type) if a.kind_of? ModRM and arg.type.name != :__int64
      unuse a
      instr 'push', a
    }

    regargs_unuse = []
    regargsmask.zip(expr.rexpr).each { |ra, arg|
      next if not arg or not ra
      a = c_cexpr_inner(arg)
      a = resolve_address a if a.kind_of? Address
      r = Reg.new(ra, a.respond_to?(:sz) ? a.sz : 64)
      instr 'mov', r, a if not a.kind_of? Reg or a.val != r.val
      unuse a
      regargs_unuse << r if not @state.inuse.include? ra
      inuse r
    }
    instr 'sub', Reg.new(4, 64), Expression[@state.args_space] if @state.args_space > 0	# TODO prealloc that at func start

    if ft.kind_of? C::Function and ft.varargs and @state.args_space == 0
      # gcc stores here the nr of xmm args passed, real args are passed the standard way
      # TODO check visualstudio/ms ABI
      instr 'xor', rax, rax
      inuse rax
    end


    if expr.lexpr.kind_of? C::Variable and expr.lexpr.type.kind_of? C::Function
      instr 'call', Expression[expr.lexpr.name]
    else
      ptr = c_cexpr_inner(expr.lexpr)
      unuse ptr
      ptr = make_volatile(ptr, expr.lexpr.type) if ptr.kind_of? Address
      instr 'call', ptr
    end
    regargs_unuse.each { |r| unuse r }
    argsz = @state.args_space + stackargs.length * 8
    argsz += 8 if stackalign
    instr 'add', Reg.new(4, @cpusz), Expression[argsz] if argsz > 0

    @state.abi_flushregs_call.each { |reg| flushcachereg reg }
    @state.used |= backup
    if @state.used.include?(0)
      retreg = inuse findreg
    else
      retreg = inuse getreg(0)
    end
    backup.reverse_each { |reg|
      if retreg.kind_of? Reg and reg == 0
        instr 'pop', Reg.new(retreg.val, 64)
        instr 'xchg', Reg.new(reg, 64), Reg.new(retreg.val, 64)
      else
        instr 'pop', Reg.new(reg, 64)
      end
    }
    retreg
  end

  # compiles/optimizes arithmetic operations
  def c_cexpr_inner_arith(l, op, r, type)
    # optimizes *2 -> <<1
    if r.kind_of? Expression and (rr = r.reduce).kind_of? ::Integer
      if type.integral? or type.pointer?
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
      end
    end

    if type.float?
      raise 'float unhandled'
    else
      c_cexpr_inner_arith_int(l, op, r, type)
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
      instr op, l, i_to_i32(r)
    when 'shr', 'sar', 'shl'
      if r.kind_of? Expression
        instr op, l, r
      else
        # XXX bouh
        r = make_volatile(r, C::BaseType.new(:__int8, :unsigned))
        unuse r
        if r.val != 1
          rcx = Reg.new(1, 64)
          instr 'xchg', rcx, Reg.new(r.val, 64)
          l = Reg.new(r.val, l.sz) if l.kind_of? Reg and l.val == 1
        end
        instr op, l, Reg.new(1, 8)
        instr 'xchg', rcx, Reg.new(r.val, 64) if r.val != 1
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
      rax = Reg.from_str 'rax'
      rdx = Reg.from_str 'rdx'
      if @state.used.include? rax.val and lv != rax.val
        instr 'push', rax
        saved_rax = true
      end
      if @state.used.include? rdx.val and lv != rdx.val
        instr 'push', rdx
        saved_rdx = true
      end

      instr 'mov', rax, l if lv != rax.val

      if r.kind_of? Expression
        instr 'push', r
        rsp = Reg.from_str 'rsp'
        r = ModRM.new(@cpusz, 64, nil, nil, rsp, nil)
        need_pop = true
      end

      if type.specifier == :unsigned
        instr 'mov', rdx, Expression[0]
        instr 'div', r
      else
        instr 'cdq'
        instr 'idiv', r
      end
      unuse r

      instr 'add', rsp, 8 if need_pop

      if op == 'div'
        instr 'mov', l, rax if lv != rax.val
      else
        instr 'mov', l, rdx if lv != rdx.val
      end

      instr 'pop', rdx if saved_rdx
      instr 'pop', rax if saved_rax
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
      r = make_volatile(r, expr.type) if r.kind_of? ModRM and l.kind_of? ModRM
      if l.kind_of? Expression
        o = { :< => :>, :> => :<, :>= => :<=, :<= => :>= }[o] || o
        l, r = r, l
      end
      unuse l, r
      if expr.lexpr.type.integral? or expr.lexpr.type.pointer?
        r = Reg.new(r.val, l.sz) if r.kind_of? Reg and r.sz != l.sz	# XXX
        instr 'cmp', l, i_to_i32(r)
      elsif expr.lexpr.type.float?
        raise 'float unhandled'
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
    instr 'mov', Reg.new(0, r.sz), r if r.val != 0
  end

  def c_asm(stmt)
    if stmt.output or stmt.input or stmt.clobber
      raise # TODO (handle %%0 => rax, gas, etc)
    else
      raise 'asm refering variables unhandled' if @state.func.initializer.symbol.keys.find { |sym| stmt.body =~ /\b#{Regexp.escape(sym)}\b/ }
      @source << stmt.body
    end
  end

  def c_init_state(func)
    @state = State.new(func)
    args = func.type.args.dup
    if @parser.lexer.definition['__MS_X86_64_ABI__']
      @state.args_space = 32
      @state.regargs = [1, 2, 8, 9]
    else
      @state.args_space = 0
      @state.regargs = [7, 6, 2, 1, 8, 9]
    end
    c_reserve_stack(func.initializer)
    off = @state.offset.values.max.to_i
    off = 0 if off < 0

    argoff = 2*8 + @state.args_space
    rlist = @state.regargs.dup
    args.each { |a|
      if a.has_attribute_var('register')
        off = c_reserve_stack_var(a, off)
        @state.offset[a] = off
      elsif r = rlist.shift
        if @state.args_space > 0
          # use reserved space to spill regargs
          off = -16-8*@state.regargs.index(r)
        else
          off = c_reserve_stack_var(a, off)
        end
        @state.offset[a] = off
      else
      @state.offset[a] = -argoff
        argoff = (argoff + sizeof(a) + 7) / 8 * 8
      end
    }
    if not @state.offset.values.grep(::Integer).empty?
      @state.saved_rbp = Reg.new(5, @cpusz)
      @state.used << 5
    end
  end

  def c_prolog
    localspc = @state.offset.values.grep(::Integer).max
    return if @state.func.attributes.to_a.include? 'naked'
    @state.dirty -= @state.abi_trashregs
    if localspc
      localspc = (localspc + 7) / 8 * 8
      if @state.args_space > 0 and (localspc/8 + @state.dirty.length) & 1 == 1
        # ensure 16-o stack align on windows
        localspc += 8
      end
      ebp = @state.saved_rbp
      esp = Reg.new(4, ebp.sz)
      instr 'push', ebp
      instr 'mov', ebp, esp
      instr 'sub', esp, Expression[localspc] if localspc > 0

      rlist = @state.regargs.dup
      @state.func.type.args.each { |a|
        if rn = a.has_attribute_var('register')
          r = Reg.from_str(rn).val
        elsif r = rlist.shift
        else next
        end
        v = findvar(a)
        instr 'mov', v, Reg.new(r, v.sz)
      }
    elsif @state.args_space > 0 and @state.dirty.length & 1 == 0
      instr 'sub', Reg.new(4, @cpusz), Expression[8]
    end
    @state.dirty.each { |reg|
      instr 'push', Reg.new(reg, @cpusz)
    }
  end

  def c_epilog
    return if @state.func.attributes.to_a.include? 'naked'
    @state.dirty.reverse_each { |reg|
      instr 'pop', Reg.new(reg, @cpusz)
    }
    if ebp = @state.saved_rbp
      instr 'mov', Reg.new(4, ebp.sz), ebp
      instr 'pop', ebp
    elsif @state.args_space > 0 and @state.dirty.length & 1 == 0
      instr 'add', Reg.new(4, @cpusz), Expression[8]
    end
    instr 'ret'
  end

  def c_program_epilog
  end

  def check_reserved_name(var)
    Reg.s_to_i[var.name]
  end
end

  def new_ccompiler(parser, exe=ExeFormat.new)
    exe.cpu = self if not exe.instance_variable_get('@cpu')
    CCompiler.new(parser, exe)
  end
end
end
