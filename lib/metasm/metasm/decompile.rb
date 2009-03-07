require 'metasm/decode'
require 'metasm/parse_c'

module Metasm
class Decompiler
	attr_accessor :dasm, :c_parser

	def initialize(dasm, cp = dasm.c_parser)
		@dasm = dasm
		@c_parser = cp || @dasm.cpu.new_cparser
	end

	# decompile a function, decompiling subfunctions as needed
	def decompile_func(entry)
		entry = @dasm.normalize entry
		return if not @dasm.decoded[entry]
		puts "decompiling #{Expression[entry]}" if $VERBOSE

		# create a new toplevel function to hold our code
		func = C::Variable.new
		func.name = @dasm.auto_label_at(entry, 'func')
		func.type = C::Function.new C::BaseType.new(:void)
		if @c_parser.toplevel.symbol[func.name]
			if not @c_parser.toplevel.statements.grep(C::Declaration).find { |decl| decl.var.name == func.name }
				# recursive dependency: declare prototype
				@c_parser.toplevel.statements << C::Declaration.new(func)
			end
			return
		end
		@c_parser.toplevel.symbol[func.name] = func

		# find decodedinstruction blocks constituing the function
		# TODO merge sequencial blocks with useless jmp (poeut) to improve dependency graph later
		myblocks = decompile_func_listblocks(entry)

		puts "finding vars..." if $VERBOSE
		# [esp+8] => arg_4
		decompile_makestackvars entry, myblocks.map { |b, to| @dasm.decoded[b].block }

		puts "finding deps..." if $VERBOSE
		# find stack variable dependencies
		deps = decompile_func_finddeps(myblocks)

		puts "do decomp" if $VERBOSE
		scope = func.initializer = C::Block.new(@c_parser.toplevel)
		# di blocks => raw c statements, declare variables
		stmts = decompile_blocks(myblocks, deps, scope)

		# scope contains only declarations for now
		scope.statements = scope.statements.sort_by { |sm| sm.var.name[4..-1].to_s.to_i(16) }

		# find func prototype
		func.type.args = []
		scope.statements.dup.each { |sm|
			if sm.var.name =~ /arg_([0-9a-f]+)/i
				func.type.args << scope.statements.delete(sm).var
			end
		}
		func.type.args = func.type.args.sort_by { |sm| sm.name[/arg_([0-9a-f]+)/i, 1].to_i(16) }

		# populate statements
		scope.statements.concat stmts

		# goto bla ; bla: goto blo => goto blo ;; goto bla ; bla: return => return
		decompile_simplify_goto(scope)

		# change if() goto to if, if/else, while
		decompile_match_controlseq(scope)

		# remove unreferenced labels
		decompile_remove_labels(scope)

		case ret = scope.statements.last
		when C::CExpression; puts "no return at end of func"
		when C::Return
			if not ret.value
				scope.statements.pop
			else
				func.type.type = C::BaseType.new(:int)
			end
		end

		# infer variable types
		decompile_c_types(scope)

		# add unused args to arglist to preserve the func ABI
		# XXX shouldn't use the arg_XX form
		argoff = varname_to_stackoff('arg_0')
		args = []
		func.type.args.each { |a|
			# XXX misalignment ?
			curoff = varname_to_stackoff(a.name)
			while curoff > argoff
				wantarg = C::Variable.new
				wantarg.name = stackoff_to_varname(argoff).to_s
				wantarg.type = C::BaseType.new(:int)
				args << wantarg
				scope.symbol[wantarg.name] = wantarg
				argoff += @dasm.cpu.size/8
			end
			args << a
		}
		func.type.args = args

		@c_parser.toplevel.statements << C::Declaration.new(func)
	end

	# return an array of [address of block start, list of block to]]
	# decompile subfunctions
	def decompile_func_listblocks(entry)
		blocks = []
		entry = dasm.normalize entry
		todo = [entry]
		while a = todo.pop
			next if blocks.find { |aa, at| aa == a }
			next if not di = @dasm.decoded[a]
			next if not di.kind_of? DecodedInstruction
			blocks << [a, []]
			di.block.each_to { |ta, type|
				next if type == :indirect
				ta = dasm.normalize ta
				if @dasm.function[ta] and type != :subfuncret	# and di.block.to_subfuncret # XXX __attribute__((noreturn)) ?
					decompile_func(ta) if ta != entry
				else
					@dasm.auto_label_at(ta, 'label') if blocks.find { |aa, at| aa == ta }
					blocks.last[1] |= [ta]
					todo << ta
				end
			}
		end
		blocks
	end

	# patches instruction's backtrace_binding to replace [frame+X] => :varX
	def decompile_makestackvars(funcstart, blocks)
		tovar = proc { |di, e, i_s|
			case e
			when Expression
				r = tovar[di, e.rexpr, i_s]
				if r.kind_of? ::Symbol and e.op == :+ and not e.lexpr
					r
				else
					Expression[tovar[di, e.lexpr, i_s], e.op, r]
				end
			when Indirection
				# XXX this includes never used vars (eg slots used to
				# save reg across the whole function) and subfunction
				# args slots ; they will be filtered out later
				p_ini = @dasm.backtrace(e.target, di.address, :include_start => i_s, :snapshot_addr => funcstart).first
				stackoff = Expression[p_ini, :-, :esp].reduce	# TODO move to ia32/decompile
				if stackoff.kind_of? Integer
					# XXX lose ind.length ?
					stackoff_to_varname(stackoff)
				else
					Indirection[tovar[di, e.target, i_s], e.len]
				end
			else e
			end
		}

		blocks.each { |block|
			block.list.each { |di|
				bd = @dasm.cpu.get_backtrace_binding(di)
				bd.each { |k, v|
					# think about push/pop: key need to include_start, value don't
					bd[tovar[di, k, true]] = Expression[tovar[di, v, false]]
				}
				di.backtrace_binding = bd
			}
		}
	end

	# give a name to a stackoffset (relative to start of func)
	# 4 => :arg_0, -8 => :var_4 etc
	def stackoff_to_varname(off)
		if off > 0
			'arg_%X' % ( off-@dasm.cpu.size/8)	#  4 => arg_0,  8 => arg_4..
		elsif off == 0
			'retaddr'
		else
			'var_%X' % (-off-@dasm.cpu.size/8)	# -4 => var_0, -8 => var_4..
		end.to_sym
	end

	def varname_to_stackoff(var)
		case var.to_s
		when /^arg_(.*)/;  $1.to_i(16) + @dasm.cpu.size/8
		when /^var_(.*)/; -$1.to_i(16) - @dasm.cpu.size/8
		when 'retaddr'; 0
		end
	end

	# list variable dependency for each block, remove useless writes
	# returns { blockaddr => [list of vars that are needed by a following block] }
	def decompile_func_finddeps(blocks)
		deps_r = {} ; deps_w = {} ; deps_to = {}
		deps_subfunc = {} ; deps_subfuncw = {}	# things read/written by subfuncs

		# find read/writes by each block
		blocks.each { |b, to|
			deps_r[b] = [] ; deps_w[b] = [] ; deps_to[b] = to
			deps_subfunc[b] = [] ; deps_subfuncw[b] = []

			blk = @dasm.decoded[b].block
			blk.list.each { |di|
				a = di.backtrace_binding.values
				w = di.backtrace_binding.keys
				deps_r[b] |= a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - deps_w[b]
				deps_w[b] |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
			}
			stackoff = nil
			blk.each_to_normal { |t|
				t = backtrace_target(t, blk.list.last.address)
				next if not t = @c_parser.toplevel.symbol[t]
				stackoff ||= Expression[@dasm.backtrace(:esp, blk.list.last.address, :snapshot_addr => blocks.first[0]).first, :-, :esp].reduce

				# things that are needed by the subfunction
				args = t.type.args.map { |a| a.type }
				if t.attributes.to_a.include? 'fastcall'
					deps_subfunc[b] |= [:ecx, :edx]
					# XXX the two first args with size <= int are not necessarily nr 0 and nr 1..
					args.shift ; args.shift
				end
				off = stackoff
				args.each { |a|
					# XXX assume all args are sizeof() <= int
					# TODO if the arg is a struct/pointer, the func also depends on the data pointed to
					deps_subfunc[b] |= [stackoff_to_varname(off)]
					off += @dasm.cpu.size/8
				}
			}
			if stackoff
				deps_r[b] |= deps_subfunc[b] - deps_w[b]
				deps_w[b] |= deps_subfuncw[b] = [:eax, :ecx, :edx]
			end
			if to.empty?
				deps_subfunc[b] |= [:eax]	# current function return value
			end
		}

		# remove writes from a block if no following block read the value
		deps_w.each { |b, deps|
			deps.delete_if { |dep|
				next true if dep == :esp		# never relevant (cross fingers)
				#next if dep.to_s =~ /^(var_|arg_)/	# keep stack sync
				next if deps_subfunc[b].include? dep	# arg to a function called by the block
				next true if deps_subfuncw[b].include? dep	# thing written by the function
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

		deps_w
	end

	def decompile_blocks(myblocks, deps, scope, nextaddr = nil)
		stmts = []
		func_entry = myblocks.first[0]
		until myblocks.empty?
			b, to = myblocks.shift
			if l = @dasm.prog_binding.index(b)
				stmts << C::Label.new(l)
			end

			# list of assignments [[dest reg, expr assigned]]
			ops = []
			# reg binding (reg => value, values.externals = regs at block start)
			binding = {}
			# Expr => CExpr
			ce  = proc { |*e|
				e = Expression[Expression[*e].reduce]
				decompile_cexpr(e, scope)
			}
			# Expr => Expr.bind(binding) => CExpr
			ceb = proc { |*e| ce[Expression[*e].bind(binding)] }
			# shortcut to global funcname => Var (ext functions, e.g. malloc)
			ts = @c_parser.toplevel.symbol

			# dumps a CExprs that implements an assignment to a reg (uses ops[], patches op => [reg, nil])
			commit = proc {
				#ops.each { |r, v| stmts << ce[r, :'=', v] }	# doesn't work, ops may have internal/circular deps
				#binding = {}
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
					stmts << ce[k, :'=', e]
				}
			}

			# go !
			# TODO not Ia32 specific
			@dasm.decoded[b].block.list.each { |di|
				a = di.instruction.args
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					# conditional jump
					# XXX switch/indirect/multiple jmp
					commit[]
					n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
					stmts << C::If.new(ceb[@dasm.cpu.decode_cc_to_expr(di.opcode.name[1..-1])], C::Goto.new(n))
					to.delete @dasm.normalize(n)
					next
				end

				case di.opcode.name
				when 'ret'
					commit[]
					stmts << C::Return.new(nil)
				when 'call'	# :saveip
					n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
					args = []
					if t = @c_parser.toplevel.symbol[n] and t.type.args
						# XXX see remarks in #finddeps
						stackoff = Expression[@dasm.backtrace(:esp, di.address, :snapshot_addr => func_entry), :-, :esp].reduce
						args_todo = t.type.args.dup
						args = []
						if t.attributes.to_a.include? 'fastcall'
							a = args_todo.shift
							mask = (1 << (8*@c_parser.sizeof(a))) - 1
							args << ceb[:ecx, :&, mask]
							binding.delete :ecx

							a = args_todo.shift
							mask = (1 << (8*@c_parser.sizeof(a))) - 1	# char => dl
							args << ceb[:edx, :&, mask]
							binding.delete :edx
						end
						args_todo.each { |a|
							if stackoff.kind_of? Integer
								var = stackoff_to_varname(stackoff)
								stackoff += @dasm.cpu.size/8
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
						if not ts[n]
							# internal functions are predeclared, so this one is extern
							ts[n] = C::Variable.new
							ts[n].name = n
							ts[n].type = C::Function.new C::BaseType.new(:int)
							@c_parser.toplevel.statements << C::Declaration.new(ts[n])
						end
						commit[]
						stmts << C::CExpression.new(ts[n], :funcall, args, ts[n].type.type)
					else
						# indirect funcall
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:int))
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto)) if not fptr.kind_of? C::CExpression	# cast
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto))
						commit[]
						stmts << C::CExpression.new(fptr, :funcall, args, proto.type)
					end
				when 'jmp'
					if di.block.to_normal.to_a.length > 1
						n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:void))
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto)) if not fptr.kind_of? C::CExpression	# cast
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto))
						commit[]
						stmts << C::CExpression.new(fptr, :funcall, [], proto.type)
					end
					# XXX bouh
					# TODO need to know for which instructions the bt_binding is accurate
				when 'push', 'pop', 'mov', 'add', 'sub', 'or', 'xor', 'and', 'not', 'mul', 'div', 'idiv', 'imul', 'shr', 'shl', 'sar', 'test', 'cmp', 'inc', 'dec', 'lea', 'movzx', 'movsx', 'neg', 'cdq'
					di.backtrace_binding.each { |k, v|
						if k.kind_of? ::Symbol or (k.kind_of? Indirection and Expression[k.target, :-, :esp].reduce.kind_of? ::Integer)
							ops << [k, v]
						else
							stmts << ceb[k, :'=', v]
						end
					}
					update = {}
					di.backtrace_binding.each { |k, v|
						next if not k.kind_of? ::Symbol
						update[k] = Expression[Expression[v].bind(binding).reduce]
					}
					binding.update update
				else
					commit[]
					stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
				end
			}
			commit[]

			case to.length
			when 0
				if not myblocks.empty? and @dasm.decoded[b].block.list.last.instruction.opname != 'ret'
					puts "  block #{Expression[b]} has no to and don't end in ret"
				end
			when 1
				if (myblocks.empty? ? nextaddr != to[0] : myblocks.first.first != to[0])
					stmts << C::Goto.new(@dasm.auto_label_at(to[0], 'unknown_goto'))
				end
			else
				puts "  block #{Expression[b]} with multiple to"
			end
		end
		stmts
	end

	# backtraces an expression from addr
	# returns an integer, a label name, or an Expression
	def backtrace_target(expr, addr)
		if n = @dasm.backtrace(expr, addr).first
			n = Expression[n].reduce_rec
			@dasm.prog_binding.index(n) || n
		end
	end

	# turns an Expression to a CExpression, create+declares needed variables in scope
	def decompile_cexpr(e, scope)
		case e
		when Expression
			if e.op == :'=' and e.rexpr.kind_of? Expression and e.rexpr.lexpr == e.lexpr
				r = e.rexpr
				r.op, r.rexpr = :-, -r.rexpr if r.op == :+ and r.rexpr.kind_of? Integer and r.rexpr < 0
				case r.op
				when :+; e = Expression[e.lexpr, :'+=', r.rexpr]	# cannot ++ until we have the type (ptr etc)
				when :-; e = Expression[e.lexpr, :'-=', r.rexpr]
				when :^; e = Expression[e.lexpr, :'^=', r.rexpr]
				end
			end
			if e.op == :'=' and e.lexpr.kind_of? ::String and e.lexpr =~ /^dummy_metasm_/
				decompile_cexpr(e.rexpr, scope)
			elsif e.op == :'&' and e.rexpr == 0xffff_ffff
				decompile_cexpr(e.lexpr, scope)
			elsif e.op == :+ and e.rexpr.kind_of? ::Integer and e.rexpr < 0
				decompile_cexpr(Expression[e.lexpr, :-, -e.rexpr], scope)
			elsif (e.op == :== or e.op == :'!=') and e.rexpr == 0 and e.lexpr.kind_of? Expression and e.lexpr.op == :+
				decompile_cexpr(Expression[e.lexpr.lexpr, e.op, [:-, e.lexpr.rexpr]].reduce, scope)
			elsif (e.op == :== or e.op == :'!=') and e.rexpr == 0 and l = e.lexpr and l.kind_of? Expression and
				l.op == :& and l.rexpr == 1 and l = l.lexpr and l.op == :>> and l.rexpr == @dasm.cpu.size-1
				decompile_cexpr(Expression[l.lexpr, ((e.op == :==) ? :>= : :<), 0].reduce, scope)
			elsif e.lexpr
				a = decompile_cexpr(e.lexpr, scope)
				C::CExpression.new(a, e.op, decompile_cexpr(e.rexpr, scope), a.type)
			elsif e.op == :+
				decompile_cexpr(e.rexpr, scope)
			else
				a = decompile_cexpr(e.rexpr, scope)
				C::CExpression.new(nil, e.op, a, a.type)
			end
		when Indirection
			# XXX int *p ; p + 4*z  =>  p + z
			p = decompile_cexpr(e.target, scope)
			p = C::CExpression.new(nil, nil, p, C::Pointer.new(C::BaseType.new(e.len == 4 ? :int : :char)))
			p = C::CExpression.new(nil, nil, p, p.type) if not p.rexpr.kind_of? C::CExpression
			C::CExpression.new(nil, :*, p, p.type.type)
		when ::Symbol, ::String
			name = e.to_s
			if not s = scope.symbol_ancestors[name]
				s = C::Variable.new
				s.type = C::BaseType.new(:int)
				if e.kind_of? ::String
					s.storage = :extern
				elsif name[0,4] != 'var_' and name[0,4] != 'arg_'
					s.storage = :register
				end
				s.name = name
				scope.symbol[s.name] = s
				scope.statements << C::Declaration.new(s)
			end
			s
		when ::Integer
			C::CExpression.new(nil, nil, e, C::BaseType.new(:int))
		when C::CExpression
			e
		else puts "decompile_cexpr unhandled #{e.inspect}" ; C::CExpression.new(nil, nil, e, C::BaseType.new(:void))
		end
	end

	# simplify goto -> goto
	# iterative process, to not infinite loop on b:goto a; a:goto b;
	# TODO multipass ? (goto a -> goto b -> goto c -> goto d)
	# remove last return if not useful
	def decompile_simplify_goto(scope)
		cntr = -1

		simpler_goto = proc { |g|
			case ret = g
			when C::Goto
				# return a new goto
				decompile_walk(scope) { |s|
					if s.kind_of? C::Block and l = s.statements.grep(C::Label).find { |l| l.name == g.target }
						case nt = s.statements[s.statements.index(l)..-1].find { |ss| not ss.kind_of? C::Label }
						when C::Goto; ret = nt
						end
					end
				}
			when C::Return
				# XXX if () { return } else { return }
				lr = scope.statements.last
				if g != lr and lr.kind_of? C::Return and g.value == lr.value
					if not scope.statements[-2].kind_of? C::Label
						scope.statements.insert(-2, C::Label.new("ret_#{cntr += 1}", nil))
					end
					ret = C::Goto.new(scope.statements[-2].name)
				end
			end
			ret
		}

		decompile_walk(scope) { |s|
			case s
			when C::Block
				s.statements.each { |ss|
					s.statements[s.statements.index(ss)] = simpler_goto[ss]
				}
			when C::If
				s.bthen = simpler_goto[s.bthen]
			end
		}
	end

	# changes ifgoto, goto to while/ifelse..
	def decompile_match_controlseq(scope)
		scope.statements = decompile_cseq_if(scope.statements, scope)
		decompile_cseq_while(scope.statements)
	end

	# ifgoto => ifthen
	# ary is an array of statements where we try to find if () {} [else {}]
	# recurses to then/else content
	def decompile_cseq_if(ary, scope)
		# helper to negate the if condition
		negate = proc { |ce|
			if ce.kind_of? C::CExpression and nop = { :== => :'!=', :'!=' => :==, :> => :<=, :>= => :<, :< => :>=, :<= => :>, :'!' => :'!' }[ce.op]
				if nop == :'!'
					ce.rexpr
				elsif nop == :== and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 0 and
					ce.lexpr.kind_of? C::CExpression and [:==, :'!=', :>, :<, :>=, :<=, :'!'].include? ce.lexpr.op
					ce.lexpr
				else
					C::CExpression.new(ce.lexpr, nop, ce.rexpr, ce.type)
				end
			else
				C::CExpression.new(nil, :'!', ce, C::BaseType.new(:int))
			end
		}

		# the array of decompiled statements to use as replacement
		ret = []
		# list of labels appearing in ary
		inner_labels = ary.grep(C::Label).map { |l| l.name }
		while s = ary.shift
			# "forward" ifs only
			if s.kind_of? C::If and s.bthen.kind_of? C::Goto and l = ary.grep(C::Label).find { |l| l.name == s.bthen.target }
				# if {goto l;} a; l: => if (!) {a;}
				s.test = negate[s.test]
				s.bthen = C::Block.new(scope)
				s.bthen.statements = decompile_cseq_if(ary[0...ary.index(l)], scope)
				bts = s.bthen.statements
				ary[0...ary.index(l)] = []

				# if { a; goto outer; } b; return; => if (!) { b; return; } a; goto outer;
				if bts.last.kind_of? C::Goto and not inner_labels.include? bts.last.target and g = ary.find { |ss| ss.kind_of? C::Goto or ss.kind_of? C::Return } and g.kind_of? C::Return
					s.test = negate[s.test]
					ary[0..ary.index(g)], bts[0..-1] = bts, ary[0..ary.index(g)]
				end

				# if { a; goto l; } b; l: => if {a;} else {b;}
				if bts.last.kind_of? C::Goto and l = ary.grep(C::Label).find { |l| l.name == bts.last.target }
					s.belse = C::Block.new(scope)
					s.belse.statements = decompile_cseq_if(ary[0...ary.index(l)], scope)
					ary[0...ary.index(l)] = []
					bts.pop
				end

				# if { a; l: b; goto any;} c; goto l; => if { a; } else { c; } b; goto any;
				if not s.belse and (bts.last.kind_of? C::Goto or bts.last.kind_of? C::Return) and g = ary.grep(C::Goto).first and l = bts.grep(C::Label).find { |l| l.name == g.target }
					s.belse = C::Block.new(scope)
					s.belse.statements = decompile_cseq_if(ary[0...ary.index(g)], scope)
					ary[0..ary.index(g)], bts[bts.index(l)..-1] = bts[bts.index(l)..-1], []
				end

				# if { a; b; c; } else { d; b; c; } => if {a;} else {d;} b; c;
				if s.belse
					bes = s.belse.statements
					while not bts.empty?
						if bts.last.kind_of? C::Label; ary.unshift bts.pop
						elsif bes.last.kind_of? C::Label; ary.unshift bes.pop
						elsif bts.last.to_s == bes.last.to_s; ary.unshift bes.pop ; bts.pop
						else break
						end
					end

					# if () { a; } else { b; } => if () { a; } else b;
					# if () { a; } else {} => if () { a; }
					case bes.length
					when 0; s.belse = nil
					when 1; s.belse = bes.first
					end
				end

				# if () {} else { a; } => if (!) { a; }
				# if () { a; } => if () a;
				case bts.length
				when 0; s.test, s.bthen, s.belse = negate[s.test], s.belse, nil if s.belse
				when 1; s.bthen = bts.first
				end
			end
			ret << s
		end
		ret
	end

	def decompile_cseq_while(ary)
		# find the next instruction that is not a label
		ni = proc { |l| ary[ary.index(l)..-1].find { |s| not s.kind_of? C::Label } }
		ary.each { |s|
			case s
			when C::Label
				if ss = ni[s] and ss.kind_of? C::If and not ss.belse and ss.bthen.kind_of? C::Block and ss.bthen.statements.last.kind_of? C::Goto and ss.bthen.statements.last.target == s.name
					ss.bthen.statements.pop
					if l = ary[ary.index(ss)+1] and l.kind_of? C::Label
						ss.bthen.statements.grep(C::If).each { |i|
							i.bthen = C::Break.new if i.bthen.kind_of? C::Goto and i.bthen.target == l.name
						}
					end
					ary[ary.index(ss)] = C::While.new(ss.test, ss.bthen)
				end
			when C::If
				decompile_cseq_while(s.bthen.statements) if s.bthen.kind_of? C::Block
				decompile_cseq_while(s.belse.statements) if s.belse.kind_of? C::Block
			when C::While
				decompile_cseq_while(s.body.statements) if s.body.kind_of? C::Block
			end
		}
	end

	def decompile_remove_labels(scope)
		decompile_walk(scope) { |s|
			next if not s.kind_of? C::Block
			s.statements.delete_if { |l|
				if l.kind_of? C::Label
					notfound = true
					decompile_walk(scope) { |ss| notfound = false if ss.kind_of? C::Goto and ss.target == l.name}
				end
				notfound
			}
		}
	end

	def decompile_c_types(scope)
		# pass 1: find variables type
		types = {}

		# scan for var = int
		decompile_walk(scope) { |ce| decompile_walk_ce(ce) { |ce|
			if ce.op == :'=' and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == nil and ce.rexpr.rexpr.kind_of? ::Integer and ce.rexpr.rexpr.abs < 0x10000
				v = ce.lexpr
				if v.kind_of? C::Variable and v.storage != :register
					types[v.name] ||= ce.rexpr.type
				end
			elsif ce.op == :'=' and ce.rexpr.kind_of? C::Variable and types[ce.rexpr.name]
				v = ce.lexpr
				if v.kind_of? C::Variable and v.storage != :register
					types[v.name] ||= types[ce.rexpr.name]
				end
			end
		} }

		# scan for *(bla*)x
		decompile_walk(scope) { |ce| decompile_walk_ce(ce) { |ce|
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == nil and ce.rexpr.rexpr.kind_of? C::CExpression
				p = ce.rexpr.rexpr
				if p.op == nil and p.rexpr.kind_of? C::Variable and p.rexpr.storage != :register
					types[p.rexpr.name] ||= ce.rexpr.type
				elsif p.op == :+ and p.lexpr
					if p.lexpr.kind_of? C::Variable and p.lexpr.storage != :register and ((p.rexpr.kind_of? C::Variable and types[p.rexpr.name] and types[p.rexpr.name].integral?) or (p.rexpr.kind_of? C::CExpression and not p.rexpr.op and p.rexpr.rexpr.kind_of? ::Integer))
						types[p.lexpr.name] ||= ce.rexpr.type
					elsif p.rexpr.kind_of? C::Variable and p.rexpr.storage != :register and p.lexpr.kind_of? C::Variable and types[p.lexpr.name] and types[p.lexpr.name].integral?
						types[p.rexpr.name] ||= ce.rexpr.type
					end
				end
			end
		} }

		types.each { |k, v| scope.symbol[k].type = v }
		# pass 2: fix indirections & pointer addition
		# TODO (char)toto == 42 => toto == 'A'
		decompile_walk(scope) { |ce| decompile_walk_ce(ce) { |ce|
			# *(bla*)x => *x, *(bla*)(x+2) => x[2/sizeof(*x)]
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == nil and ce.rexpr.rexpr.kind_of? C::CExpression
				p = ce.rexpr.rexpr
				if p.op == nil and p.rexpr.kind_of? C::Variable and p.rexpr.storage != :register and types[p.rexpr.name] == ce.rexpr.type
					ce.rexpr = p
					#ce.op = :[]
					#ce.lexpr = p
					#ce.rexpr = C::CExpression.new(nil, nil, 0, C::BaseType.new(:int))
				elsif p.op == :+ and p.lexpr
					if p.lexpr.kind_of? C::Variable and types[p.lexpr.name] == ce.rexpr.type
						ptr = p.lexpr
						idx = p.rexpr
					elsif p.rexpr.kind_of? C::Variable and types[p.rexpr.name] == ce.rexpr.type
						ptr = p.rexpr
						idx = p.lexpr
					else next
					end
					ce.op = :[]
					ce.lexpr = ptr
					if idx.kind_of? C::CExpression and not idx.op and idx.rexpr.kind_of? ::Integer
						ce.rexpr = idx
						idx.rexpr /= @c_parser.sizeof(ce)
					else
						sz = @c_parser.sizeof(ce)
						ce.rexpr = (sz == 1 ? idx : C::CExpression.new(idx, :/, C::CExpression.new(nil, nil, sz, idx.type), idx.type))
					end
				end
			elsif ce.op == :'+=' and ce.lexpr.kind_of? C::Variable and types[ce.lexpr.name] and types[ce.lexpr.name].kind_of? C::Pointer
				if ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer
					ce.rexpr.rexpr /= @c_parser.sizeof(ce)
				else
					sz = @c_parser.sizeof(ce)
					ce.rexpr = C::CExpression.new(ce.rexpr, :/, C::CExpression.new(nil, nil, sz, ce.rexpr.type), ce.rexpr.type) if sz != 1
				end
			end
		} }

		# TODO var++
	end

	# yield each CExpr member (recursive, allows arrays)
	def decompile_walk_ce(ce, &b)
		case ce
		when C::CExpression
			yield ce
			decompile_walk_ce(ce.lexpr, &b)
			decompile_walk_ce(ce.rexpr, &b)
		when ::Array
			ce.each { |ce| decompile_walk(ce, &b) }
		end
	end

	# yields each statement (recursive)
	def decompile_walk(scope, &b)
		case scope
		when ::Array; scope.each { |s| decompile_walk(s, &b) }
		when C::Statement
			yield scope
			case scope
			when C::Block; decompile_walk(scope.statements, &b)
			when C::If
				yield scope.test
				decompile_walk(scope.bthen, &b)
				decompile_walk(scope.belse, &b) if scope.belse
			when C::While
				yield scope.test
				decompile_walk(scope.body, &b)
			end
		end
	end
end
end
