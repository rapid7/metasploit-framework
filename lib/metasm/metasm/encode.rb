#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/parse'

module Metasm
class ExeFormat
	# encodes an Array of source (Label/Data/Instruction etc) to an EncodedData
	# resolves ambiguities using +encode_resolve+
	def assemble_sequence(seq, cpu)
		# an array of edata or sub-array of ambiguous edata
		# its last element is always an edata
		ary = [EncodedData.new]

		seq.each { |e|
			case e
			when Label: ary.last.export[e.name] = ary.last.virtsize
			when Data:  ary.last << e.encode(cpu.endianness)
			when Align, Padding:
				e.fillwith = e.fillwith.encode(cpu.endianness) if e.fillwith
				ary << e << EncodedData.new
			when Offset: ary << e << EncodedData.new
			when Instruction:
				case i = cpu.encode_instruction(self, e)
				when Array
					if i.length == 1
						ary.last << i.first
					else
						# ambiguity !
						ary << i << EncodedData.new
					end
				else
					ary.last << i
				end
			end
		}

		edata = (ary.length > 1) ? assemble_resolve(ary) : ary.shift
		edata.fixup edata.binding
		edata
	end

	# chose among multiple possible sub-EncodedData
	# assumes all ambiguous edata have the equivallent relocations in the same order
	def assemble_resolve(ary)
		startlabel = new_label

		# create two bindings where all elements are the shortest/longest possible
		minbinding = {}
		minoff = 0
		maxbinding = {}
		maxoff = 0
	
		ary.each { |elem|
			case elem
			when Array
				elem.each { |e|
					e.export.each { |label, off|
						minbinding[label] = Expression[startlabel, :+, minoff + off]
						maxbinding[label] = Expression[startlabel, :+, maxoff + off]
					}
				}
				minoff += elem.map { |e| e.virtsize }.min
				maxoff += elem.map { |e| e.virtsize }.max

			when EncodedData
				elem.export.each { |label, off|
					minbinding[label] = Expression[startlabel, :+, minoff + off]
					maxbinding[label] = Expression[startlabel, :+, maxoff + off]
				}
				minoff += elem.virtsize
				maxoff += elem.virtsize

			when Align
				minoff += 0
				maxoff += elem.val - 1

			when Padding
				# find the surrounding Offsets and compute the largest/shortest edata sizes to determine min/max length for the padding
				prevoff = ary[0..ary.index(elem)].grep(Offset).last
				nextoff = ary[ary.index(elem)..-1].grep(Offset).first
				raise EncodeError, 'need .offset after .pad' if not nextoff

				previdx = prevoff ? ary.index(prevoff) + 1 : 0
				surround = ary[previdx..ary.index(nextoff)-1]
				surround.delete elem
				if surround.find { |nelem| nelem.kind_of? Padding }
					raise EncodeError, 'need .offset beetween two .pad'
				end
				if surround.find { |nelem| nelem.kind_of? Align and ary.index(nelem) > ary.index(elem) }
					raise EncodeError, 'cannot .align after a .pad'
				end

				lenmin = lenmax = nextoff.val - (prevoff ? prevoff.val : 0)
				surround.each { |nelem|
					case nelem
					when Array
						lenmin -= nelem.map { |e| e.virtsize }.max
						lenmax -= nelem.map { |e| e.virtsize }.min
					when EncodedData
						lenmin -= nelem.virtsize
						lenmax -= nelem.virtsize
					when Align
						lenmin -= nelem.val - 1
						lenmax -= 0
					end
				}
				raise EncodeError, "no room for .pad before '.offset #{nextoff.val}' at #{Backtrace::backtrace_str(nextoff.backtrace)}, need at least #{-lenmax} more bytes" if lenmax < 0
				minoff += lenmin
				maxoff += [lenmax, 0].max

			when Offset
				# nothing to do for now
			else
				raise "Internal error: bad object #{elem.inspect} in encode_resolve"
			end
		}

		# checks an expression linearity
		check_linear = proc { |expr|
			expr = expr.reduce if expr.kind_of? Expression
			while expr.kind_of? Expression
				case expr.op
				when :*
					if    expr.lexpr.kind_of? Numeric: expr = expr.rexpr
					elsif expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else  break
					end
				when :/, :>>, :<<
					if    expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else  break
					end
				when :+, :-
					if    not expr.lexpr:              expr = expr.rexpr
					elsif expr.lexpr.kind_of? Numeric: expr = expr.rexpr
					elsif expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else
						break if not check_linear[expr.rexpr]
						expr = expr.lexpr
					end
				else break
				end
			end

			not expr.kind_of? Expression
		}

		# now we can resolve all relocations
		# for linear expressions of internal variables (ie differences of labels from the ary):
		#  - calc target numeric bounds, and reject relocs not accepting worst case value 
		#  - else reject all but largest place available
		# then chose the shortest overall EData left
		ary.map! { |elem|
			case elem
			when Array
				# for each external, compute numeric target values using minbinding[external] and maxbinding[external]
				# this gives us all extrem values for linear expressions
				target_bounds = {}
				rec_checkminmax = proc { |idx, target, binding, extlist|
					if extlist.empty?
						(target_bounds[idx] ||= []) << target.bind(binding).reduce
					else
						rec_checkminmax[idx, target, binding.merge(extlist.last => minbinding[extlist.last]), extlist[0...-1]]
						rec_checkminmax[idx, target, binding.merge(extlist.last => maxbinding[extlist.last]), extlist[0...-1]]
					end
				}
				# biggest size disponible for this relocation (for non-linear/external)
				wantsize = {}

				elem.each { |e|
					e.reloc.sort.each_with_index { |(o, r), i|
						# has external ref
						if not r.target.bind(minbinding).reduce.kind_of?(Numeric) or not check_linear[r.target]
							# find the biggest relocation type for the current target
							wantsize[i] = elem.map { |edata|
								edata.reloc.sort[i][1].type
							}.sort_by { |type| Expression::INT_SIZE[type] }.last
						else
							rec_checkminmax[i, r.target, {}, r.target.externals]
						end
					}
				}

				# reject candidates with reloc type too small
				acceptable = elem.find_all { |edata|
					r = edata.reloc.sort
					(0...r.length).all? { |i|
						if wantsize[i]
							r[i][1].type == wantsize[i]
						else
							target_bounds[i].all? { |b| Expression.in_range?(b, r[i][1].type) }
						end
					}
				}

				raise EncodeError, "cannot find candidate in #{elem.inspect}, immediate too big #{wantsize.inspect} #{target_bounds.inspect}" if acceptable.empty?

				# keep the shortest
				acceptable.sort_by { |edata| edata.virtsize }.first
			else
				elem
			end
		}

		# assemble all parts, resolve padding sizes, check offset directives
		edata = EncodedData.new

		# fills edata with repetitions of data until targetsize
		fillwith = proc { |targetsize, data|
			if data
				while edata.virtsize + data.virtsize <= targetsize
					edata << data
				end
				if edata.virtsize < targetsize
					edata << data[0, targetsize - edata.virtsize]
				end
			else
				edata.virtsize = targetsize
			end
		}

		ary.each { |elem|
			case elem
			when EncodedData
				edata << elem
			when Align
				fillwith[EncodedData.align_size(edata.virtsize, elem.val), elem.fillwith]
			when Offset
				raise EncodeError, "could not enforce .offset #{elem.val} #{elem.backtrace}: offset now #{edata.virtsize}" if edata.virtsize != elem.val
			when Padding
				nextoff = ary[ary.index(elem)..-1].grep(Offset).first
				targetsize = nextoff.val
				ary[ary.index(elem)+1..ary.index(nextoff)-1].each { |nelem| targetsize -= nelem.virtsize }
				raise EncodeError, "no room for .pad before .offset #{nextoff.val} at #{Backtrace.backtrace_str(elem.backtrace)}: would be #{targetsize} bytes long" if targetsize < 0
				fillwith[targetsize, elem.fillwith]
			end
		}

		edata
	end
end

class Expression
	def encode(type, endianness, backtrace=nil)
		case val = reduce
		when Integer: EncodedData.new Expression.encode_immediate(val, type, endianness, backtrace)
		else          EncodedData.new('', :reloc => {0 => Relocation.new(self, type, endianness, backtrace)}, :virtsize => INT_SIZE[type]/8)
		end
	end

	def self.encode_immediate(val, type, endianness, backtrace=nil)
		raise "unsupported endianness #{endianness.inspect}" unless [:big, :little].include? endianness
		raise(EncodeError, "immediate overflow #{(Backtrace::backtrace_str(backtrace) if backtrace)}") if not in_range?(val, type)
		s = (0...INT_SIZE[type]/8).map { |i| (val >> (8*i)) & 0xff }.pack('C*')
		endianness != :little ? s.reverse : s
	end
end

class Data
	def encode(endianness)
		edata = case @data
		when :uninitialized
			EncodedData.new('', :virtsize => Expression::INT_SIZE[INT_TYPE[@type]]/8)
		when String
			# db 'foo' => 'foo' # XXX could be optimised, but should not be significant
			# dw 'foo' => "f\0o\0o\0" / "\0f\0o\0o"
			@data.unpack('C*').inject(EncodedData.new) { |ed, chr| ed << Expression.encode_immediate(chr, INT_TYPE[@type], endianness, @backtrace) }
		when Expression
			@data.encode INT_TYPE[@type], endianness
		when Array
			@data.inject(EncodedData.new) { |ed, d| ed << d.encode(endianness) }
		end

		# n times
		(0...@count).inject(EncodedData.new) { |ed, cnt| ed << edata }
	end
end

class CPU
	# returns an EncodedData or an ary of them
	# uses +#parse_arg_valid?+ to find the opcode whose signature matches with the instruction
	# uses +encode_instr_op+ (arch-specific)
	def encode_instruction(program, i)
		oplist = opcode_list_byname[i.opname].to_a.find_all { |o|
			o.args.length == i.args.length and
			o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		}
		raise EncodeError, "no matching opcode found for #{i}" if oplist.empty?
		oplist.map { |op| encode_instr_op(program, i, op) }.flatten.each { |ed| ed.reloc.each_value { |v| v.backtrace = i.backtrace } }
	end
end
end
