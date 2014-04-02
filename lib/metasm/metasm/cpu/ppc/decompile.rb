#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ppc/main'

module Metasm
class PowerPC
  # temporarily setup dasm.address_binding so that backtracking
  # stack-related offsets resolve in :frameptr (relative to func start)
  def decompile_makestackvars(dasm, funcstart, blocks)
    oldfuncbd = dasm.address_binding[funcstart]
    dasm.address_binding[funcstart] = { :sp => :frameptr }	# this would suffice, the rest here is just optimisation

    blocks.each { |block|
      yield block
    }

    dasm.address_binding[funcstart] = oldfuncbd if oldfuncbd
  end

  # list variable dependency for each block, remove useless writes
  # returns { blockaddr => [list of vars that are needed by a following block] }
  def decompile_func_finddeps(dcmp, blocks, func)
    deps_r = {} ; deps_w = {} ; deps_to = {}
    deps_subfunc = {}	# things read/written by subfuncs

    # find read/writes by each block
    blocks.each { |b, to|
      deps_r[b] = [] ; deps_w[b] = [] ; deps_to[b] = to
      deps_subfunc[b] = []

      blk = dcmp.dasm.decoded[b].block
      blk.list.each { |di|
        a = di.backtrace_binding.values
        w = []
        di.backtrace_binding.keys.each { |k|
          case k
          when ::Symbol; w |= [k]
          else a |= Expression[k].externals	# if dword [eax] <- 42, eax is read
          end
        }
        #a << :eax if di.opcode.name == 'ret'		# standard ABI

        deps_r[b] |= a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - deps_w[b]
        deps_w[b] |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
      }
      stackoff = nil
      blk.each_to_normal { |t|
        t = dcmp.backtrace_target(t, blk.list.last.address)
        next if not t = dcmp.c_parser.toplevel.symbol[t]
        t.type = C::Function.new(C::BaseType.new(:int)) if not t.type.kind_of? C::Function	# XXX this may seem a bit extreme, and yes, it is.
        stackoff ||= Expression[dcmp.dasm.backtrace(:sp, blk.list.last.address, :snapshot_addr => blocks.first[0]).first, :-, :sp].reduce
      }
      if stackoff	# last block instr == subfunction call
        deps_r[b] |= deps_subfunc[b] - deps_w[b]
        #deps_w[b] |= [:eax, :ecx, :edx]			# standard ABI
      end
    }



    # find regs read and never written (must have been set by caller and are part of the func ABI)
    uninitialized = lambda { |b, r, done|
      from = deps_to.keys.find_all { |f| deps_to[f].include? b } - done
      from.empty? or from.find { |f|
        !deps_w[f].include?(r) and uninitialized[f, r, done + [b]]
      }
    }

    # remove writes from a block if no following block read the value
    dw = {}
    deps_w.each { |b, deps|
      dw[b] = deps.reject { |dep|
        ret = true
        done = []
        todo = deps_to[b].dup
        while a = todo.pop
          next if done.include? a
          done << a
          if not deps_r[a] or deps_r[a].include? dep
            ret = false
            break
          elsif not deps_w[a].include? dep
            todo.concat deps_to[a]
          end
        end
        ret
      }
    }

    dw
  end

  def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
    scope = func.initializer
    func.type.args.each { |a| scope.symbol[a.name] = a }
    stmts = scope.statements
    func_entry = myblocks.first[0]
    until myblocks.empty?
      b, to = myblocks.shift
      if l = dcmp.dasm.get_label_at(b)
        stmts << C::Label.new(l)
      end

      # list of assignments [[dest reg, expr assigned]]
      ops = []
      # reg binding (reg => value, values.externals = regs at block start)
      binding = {}
      # Expr => CExpr
      ce  = lambda { |*e| dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope) }
      # Expr => Expr.bind(binding) => CExpr
      ceb = lambda { |*e| ce[Expression[*e].bind(binding)] }

      # dumps a CExprs that implements an assignment to a reg (uses ops[], patches op => [reg, nil])
      commit = lambda {
        deps[b].map { |k|
          [k, ops.rindex(ops.reverse.find { |r, v| r == k })]
        }.sort_by { |k, i| i.to_i }.each { |k, i|
          next if not i or not binding[k]
          e = k
          final = []
          ops[0..i].reverse_each { |r, v|
            final << r if not v
            e = Expression[e].bind(r => v).reduce if not final.include? r
          }
          ops[i][1] = nil
          binding.delete k
          stmts << ce[k, :'=', e] if k != e
        }
      }

      # go !
      dcmp.dasm.decoded[b].block.list.each_with_index { |di, didx|
        a = di.instruction.args
        if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
          # conditional jump
          commit[]
          n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
          #cc = ceb[decode_cc_to_expr(di.opcode.name[1..-1])]
          cc = ceb[:condjmp]
          stmts << C::If.new(C::CExpression[cc], C::Goto.new(n))
          to.delete dcmp.dasm.normalize(n)
          next
        end

        case di.opcode.name
        when 'blr'
          commit[]
          stmts << C::Return.new(nil)
        when 'bl'	# :saveip
          n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
          args = []
          if t = dcmp.c_parser.toplevel.symbol[n] and t.type.args
            stackoff = Expression[dcmp.dasm.backtrace(:sp, di.address, :snapshot_addr => func_entry), :-, :sp].bind(:sp => :frameptr).reduce rescue nil
            args_todo = t.type.args.dup
            args = []
            args_todo.each {
              if stackoff.kind_of? Integer
                var = Indirection[[:frameptr, :+, stackoff], @size/8]
                stackoff += @size/8
              else
                var = 0
              end
              args << ceb[var]
              binding.delete var
            }
          end
          commit[]
          #next if not di.block.to_subfuncret

          if n.kind_of? ::String
            if not f = dcmp.c_parser.toplevel.symbol[n]
              # internal functions are predeclared, so this one is extern
              f = dcmp.c_parser.toplevel.symbol[n] = C::Variable.new
              f.name = n
              f.type = C::Function.new(C::BaseType.new(:int))
              dcmp.c_parser.toplevel.statements << C::Declaration.new(f)
            end
            commit[]
          else
            # indirect funcall
            fptr = ceb[n]
            binding.delete n
            commit[]
            proto = C::Function.new(C::BaseType.new(:int))
            f = C::CExpression[[fptr], proto]
          end
          binding.delete :eax
          e = C::CExpression[f, :funcall, args]
          e = C::CExpression[ce[:eax], :'=', e, f.type.type] if deps[b].include? :eax and f.type.type != C::BaseType.new(:void)
          stmts << e
        when 'b'
          a = di.instruction.args.first
          if a.kind_of? Expression
          else
            # indirect jmp, convert to return (*fptr)();
            n = di.instruction.args.first.symbolic
            fptr = ceb[n]
            binding.delete n
            commit[]
            proto = C::Function.new(C::BaseType.new(:void))
            ret = C::Return.new(C::CExpression[[[fptr], C::Pointer.new(proto)], :funcall, []])
            class << ret ; attr_accessor :from_instr end
            ret.from_instr = di
            stmts << ret
            to = []
          end
        else
          bd = get_fwdemu_binding(di)
          if di.backtrace_binding[:incomplete_binding]
            commit[]
            stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
          else
            bd.each { |k, v|
              if k.kind_of? ::Symbol
                ops << [k, v]
              else	# memory
                stmts << ceb[k, :'=', v]
                binding.delete k
              end
            }
            update = {}
            bd.each { |k, v|
              next if not k.kind_of? ::Symbol
              update[k] = Expression[Expression[v].bind(binding).reduce]
            }
            binding.update update
          end
        end
      }
      commit[]

      case to.length
      when 0
        if not myblocks.empty? and not %w[ret jmp].include? dcmp.dasm.decoded[b].block.list.last.instruction.opname
          puts "  block #{Expression[b]} has no to and don't end in ret"
        end
      when 1
        if (myblocks.empty? ? nextaddr != to[0] : myblocks.first.first != to[0])
          stmts << C::Goto.new(dcmp.dasm.auto_label_at(to[0], 'unknown_goto'))
        end
      else
        puts "  block #{Expression[b]} with multiple to"
      end
    end
  end
end
end
