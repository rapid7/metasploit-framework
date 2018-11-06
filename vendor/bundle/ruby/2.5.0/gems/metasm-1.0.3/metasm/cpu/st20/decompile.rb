#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/st20/main'

module Metasm
class ST20
	# temporarily setup dasm.address_binding so that backtracking
	# stack-related offsets resolve in :frameptr (relative to func start)
	def decompile_makestackvars(dasm, funcstart, blocks)
		oldfuncbd = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :wspace => :frameptr }
		blocks.each { |block| yield block }
		dasm.address_binding[funcstart] = oldfuncbd
	end

	# add di-specific registry written/accessed
	def decompile_func_finddeps_di(dcmp, func, di, a, w)
		case di.instruction.opname
		when 'ret'
			a << :a if not func.type.kind_of? C::BaseType or func.type.type.name != :void	# standard ABI
		when 'in', 'out'
			a << :a << :b << :c
		end
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
					else a |= Expression[k].externals
					end
				}
				decompile_func_finddeps_di(dcmp, func, di, a, w)

				deps_r[b] |= a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - deps_w[b]
				deps_w[b] |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
			}
			blk.each_to_normal { |t|
				t = dcmp.backtrace_target(t, blk.list.last.address)
				next if not t = dcmp.c_parser.toplevel.symbol[t]
				t.type = C::Function.new(C::BaseType.new(:int)) if not t.type.kind_of? C::Function
				t.type.args.to_a.each { |arg|
					if reg = arg.has_attribute('register')
						deps_subfunc[b] |= [reg.to_sym]
					end
				}
			}
		}

		bt = blocks.transpose
		roots = bt[0] - bt[1].flatten	# XXX jmp 1stblock ?

		# find regs read and never written (must have been set by caller and are part of the func ABI)
		uninitialized = lambda { |b, r, done|
			if not deps_r[b]
			elsif deps_r[b].include?(r)
				true
			elsif deps_w[b].include?(r)
			else
				done << b
				(deps_to[b] - done).find { |tb| uninitialized[tb, r, done] }
			end
		}

		regargs = []
		register_symbols.each { |r|
			if roots.find { |root| uninitialized[root, r, []] }
				regargs << r
			end
		}

		# TODO honor user-defined prototype if available (eg no, really, eax is not read in this function returning al)
		regargs.sort_by { |r| r.to_s }.each { |r|
			a = C::Variable.new(r.to_s, C::BaseType.new(:int, :unsigned))
			a.add_attribute("register(#{r})")
			func.type.args << a
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

	def abi_funcall
		{ :retval => :a, :changed => register_symbols }
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		scope = func.initializer
		func.type.args.each { |a| scope.symbol[a.name] = a }
		stmts = scope.statements
		blocks_toclean = myblocks.dup
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

			# returns an array to use as funcall arguments
			get_func_args = lambda { |di, f|
				# XXX see remarks in #finddeps
				args_todo = f.type.args.to_a.dup
				args = []
				args_todo.each { |a_|
					if r = a_.has_attribute_var('register')
						args << Expression[r.to_sym]
					else
						args << Expression[0]
					end
				}
				args.map { |e| ceb[e] }
			}

			# go !
			dcmp.dasm.decoded[b].block.list.each_with_index { |di, didx|
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					# conditional jump
					commit[]
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					cc = ceb[:a, :'!=', 0]
					# XXX switch/indirect/multiple jmp
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n))
					to.delete dcmp.dasm.normalize(n)
					next
				end

				case di.instruction.opname
				when 'ret'
					commit[]
					ret = nil
					ret = C::CExpression[ceb[:a]] unless func.type.type.kind_of? C::BaseType and func.type.type.name == :void
					stmts << C::Return.new(ret)
				when 'fcall'	# :saveip
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					args = []
					if f = dcmp.c_parser.toplevel.symbol[n] and f.type.kind_of? C::Function and f.type.args
						args = get_func_args[di, f]
					end
					commit[]
					#next if not di.block.to_subfuncret

					if not n.kind_of? ::String or (f and not f.type.kind_of? C::Function)
						# indirect funcall
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:int))
						proto = f.type if f and f.type.kind_of? C::Function
						f = C::CExpression[[fptr], C::Pointer.new(proto)]
					elsif not f
						# internal functions are predeclared, so this one is extern
						f = C::Variable.new
						f.name = n
						f.type = C::Function.new(C::BaseType.new(:int))
						if dcmp.recurse > 0
							dcmp.c_parser.toplevel.symbol[n] = f
							dcmp.c_parser.toplevel.statements << C::Declaration.new(f)
						end
					end
					commit[]
					binding.delete :a
					e = C::CExpression[f, :funcall, args]
					e = C::CExpression[ce[:a], :'=', e, f.type.type] if deps[b].include? :a and f.type.type != C::BaseType.new(:void)
					stmts << e
				when 'in', 'out'
					if not dcmp.c_parser.toplevel.symbol["intrinsic_#{di.instruction.opname}"]
						dcmp.c_parser.parse("void intrinsic_#{di.instruction.opname}(unsigned int len, unsigned int channel, char *buf);")
					end
					f = dcmp.c_parser.toplevel.symbol["intrinsic_#{di.instruction.opname}"]
					stmts << C::CExpression.new(f, :funcall, [ceb[:a], ceb[:b], ceb[:c]], f.type.type)
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						commit[]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
					else
						update = {}
						bd.each { |k, v|
							if k.kind_of? ::Symbol and not deps[b].include? k
								ops << [k, v]
								update[k] = Expression[Expression[v].bind(binding).reduce]
							else
								stmts << ceb[k, :'=', v]
								stmts.pop if stmts.last.kind_of? C::Variable	# [:eflag_s, :=, :unknown].reduce
							end
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

		# cleanup di.bt_binding (we set :frameptr etc in those, this may confuse the dasm)
		blocks_toclean.each { |b_, to_|
			dcmp.dasm.decoded[b_].block.list.each { |di|
				di.backtrace_binding = nil
			}
		}
	end

	def decompile_check_abi(dcmp, entry, func)
		a = func.type.args || []
		a.delete_if { |arg| arg.has_attribute_var('register') and arg.has_attribute('unused') }
	end
end
end
