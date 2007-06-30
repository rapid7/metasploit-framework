#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'


module Metasm

# XXX highly experimental

class DecodedInstruction
	attr_accessor :bin_length, :instruction, :opcode, :comment
end

class Opcode
	attr_accessor :bin_mask
end

class CPU
	# takes an encoded instruction, returns a DecodedInstruction
	# if decoding fails, either di.opcode or di.instruction will be nil (depending on when the decoding problem occurs)
	def decode_instruction(program, edata, off)
		@bin_lookaside ||= build_bin_lookaside
		di = DecodedInstruction.new
		di.instruction = Instruction.new self
		pre_ptr = edata.ptr
		di.bin_length = 0
		begin
			decode_findopcode(program, edata, di)
		rescue InvalidInstruction
			di.opcode = nil
		end
		begin
			decode_instr_op(program, edata, di, off) if di.opcode
		rescue InvalidInstruction
			di.instruction = nil
		end
		di
	end

	# return the thing to backtrace that would give +value+ after the execution of this instruction
	# eg emu_backtrace('inc eax', whatever, :eax) => (:eax - 1)
	# off is the address of the beginning of di
	def emu_backtrace(di, off, value)
	end

	# returns an array of opaque cpu-specific values or immediates addresses, representing the target of the jump
	# the non-immediates will be backtracked using emu_backtrace
	def get_jump_targets(pgm, di, off)
		[]
	end
end

class InstructionBlock
	# list of DecodedInstructions
	attr_accessor :list
	# list of addresses of instructions (call/jmp), also addr of normal instruction when call flow continues to this block
	attr_accessor :from
	# list of addresses of instructions called, does include normal flow transitions (with no jump)
	attr_accessor :to
	# list of addr of instruction for which backtrace was needed, and went through us (an instruction in the end of the current block should appear here too, in case of a later split)
	attr_accessor :backtracked_for

	def initialize
		@list = []
		@from = []
		@to   = []

		@backtracked_for = []
	end
end

# expresses a pointer-like functionning
# API similar to Expression
class Indirection
	# Expression (the pointer)
	attr_accessor :target
	# the type of reference
	attr_accessor :type

	def initialize(target, type)
		@target, @type = target, type
	end

	def reduce
		Indirection.new(Expression[@target.reduce], @type)
	end
	alias reduce_rec reduce

	def bind(h)
		h.fetch(self, Indirection.new(@target.bind(h), @type))
	end

	def ==(o)
		o.class == self.class and [o.target, o.type] == [@target, @type]
	end
	def hash
		[@target, @type].hash
	end
	alias eql? ==
end

class ExeFormat
	# Hash, address => InstructionBlock
	attr_reader :block

	# returns an [encodeddata, addr of encodeddata start] with encodeddata.ptr pointing to addr
	# addr may be an address or a label name
	# default version uses each_section, which enumerates all encodeddata with their base address
	def get_section_at(addr)
		each_section { |edata, base|
			if addr.kind_of? Integer
				if addr >= base and addr < base + edata.length
					edata.ptr = addr - base
					return [edata, base]
				end
			else
				if edata.ptr = edata.export[addr]
					return [edata, base]
				end
			end
		}
		nil
	end

	# decodes instructions from an entrypoint, (tries to) follows code flow
	# TODO delay slot
	def disassemble(entrypoint = 0)
		@block ||= {}

		# hash, addr => addr of block containing the instr at this addr
		@decoded ||= {}

		# EncodedData, returned by get_section_at(addr)
		cursection = nil
		# address of first byte of cursection
		curstart = nil
		# addr of current block
		curblock = nil

		# array of couples [offset to disasm, addr of instruction pointing there]
		offsets = [[entrypoint, nil]]
		while foo = offsets.pop
			off = foo[0]
			from = foo[1]

			# resolve labels
			if off.kind_of? Integer
				if not curstart or off < curstart or off >= curstart + cursection.virtsize
					cursection, curstart = get_section_at(off)
					next if not curstart
				end	
				cursection.ptr = off - curstart
			else
				if not cursection or not cursection.export[off]
					cursection, curstart = get_section_at(off)
					next if not curstart
				else
					cursection.ptr = cursection.export[off]
				end
				off = curstart + cursection.ptr
			end

			# already gone there
			if @decoded[off]
				if curblock
					@block[curblock].to |= [off]
					from ||= @block[curblock].list[0..-2].inject(curblock) { |off, di| off + di.bin_length }
					curblock = nil
				end

				disasm_split_block(@decoded[off], off) if not @block[off]

				if from
					@block[@decoded[off]].from |= [from]
					@block[@decoded[off]].backtracked_for.each { |targetoff|
						di = @block[@decoded[targetoff]].list.inject(@decoded[targetoff]) { |o, di|
							break di if o == targetoff
							o + di.bin_length
						}
#puts "\nrebacktracking to #{'%08x' % targetoff} for #{di.instruction}"
						targets = resolve_jump_target(di, targetoff)
						offsets.unshift(*targets.reject { |t|
							@block[@decoded[targetoff]].to.include? t and @block[t] and @block[t].from.include? targetoff
						}.map { |t| [t, targetoff] })
						@block[@decoded[off]].to |= targets
					}
				end

				next
			end

			# decode the instruction
			di = @cpu.decode_instruction self, cursection, off

			# start a new block if needed
			if not curblock
				@block[curblock = off] = InstructionBlock.new
				@block[curblock].from |= [from] if from
			end

			# mark this address as already decoded
			@decoded[off] = curblock
			@block[curblock].list << di

			# invalid opcode: stop following flow
			if not di.opcode or not di.instruction
				curblock = nil
				next
			end
#puts "decoded at #{'%08x' % off} #{di.instruction}"

			# jump/call
			if di.opcode.props[:setip]
				# TODO check if where we resolved the jump is a :saveip => we have a procedure
				# handle procedures as well ('step over' (+moonwalk))
				targets = resolve_jump_target(di, off)
				di.comment = 'to ' + targets.map { |t| Expression[t] }.join(', ')

				offsets.unshift(*targets.map { |t| [t, off] })

				# end curblock
				@block[curblock].to |= targets
				# fall through
				@block[curblock].to |= [off + di.bin_length] if not di.opcode.props[:stopexec]
				curblock = nil
			elsif cursection.export.index(cursection.ptr)
				# labels only allowed at start of block: split
				@block[curblock].to |= [off + di.bin_length] if not di.opcode.props[:stopexec]
				curblock = nil
			end

			if di.opcode.props[:stopexec]
				curblock = nil
			else
				offsets << [off + di.bin_length, off]
			end
		end
	end

	# split the block (starting at oldaddr) at newaddr
	def disasm_split_block(oldaddr, newaddr)
		@block[newaddr] = InstructionBlock.new
		@block[newaddr].to = @block[oldaddr].to
		@block[oldaddr].to = [newaddr]
		@block[newaddr].backtracked_for.concat @block[oldaddr].backtracked_for
		
		# walk the block to find the splitting instruction
		curaddr = oldaddr
		i = nil
		@block[oldaddr].list.each_with_index { |di, i|
			break if curaddr == newaddr
			curaddr += di.bin_length
		}
		
		@block[newaddr].list = @block[oldaddr].list[i..-1]
		@block[oldaddr].list[i..-1] = []
		
		@block[newaddr].from = [@block[oldaddr].list[0..-2].inject(oldaddr) { |off, di| off + di.bin_length }]

		# fixup @decoded to point to the new block
		curaddr = newaddr
		@block[newaddr].list.each { |di|
			@decoded[curaddr] = newaddr
			curaddr += di.bin_length
		}
	end

	# the disassembly backtracker
	def resolve_jump_target(di, off)
		# this returns either a String (target == label) or an Integer (address) on success, or nil
		progbinding = {}
		each_section { |edata, base| progbinding.update edata.binding(base) }
		check_target = proc { |target|
			if target.kind_of? String or target.kind_of? Integer
				# puts "success: #{target.to_s 16 rescue target.inspect}"
				target
			elsif target.kind_of? Expression or target.kind_of? Indirection
				target = target.bind(progbinding).reduce
				if target.kind_of? Integer
					target
				elsif target.kind_of? Expression and target.op == :+ and not target.lexpr
					check_target[target.rexpr]
				elsif target.kind_of? Indirection
					break if not t = check_target[target.target]
					edata, base = get_section_at(t)
					break if not edata
					# puts "got ptr: #{(base + edata.ptr).to_s 16} #{target.type}"
					check_target[edata.decode_imm(target.type, @cpu.endianness)]
				end
			end
		}

		orig_off = off
		targets = @cpu.get_jump_targets(self, di, off)
		targets_found = targets.map { |t| check_target[t] }

		trace = []
		result = []
		# XXX highly suboptimal
		# [max_depth, addr of last di checked, block, index in block.list of last di checked, target to resolve]
		# TODO
		# when marking a subfunc, check all paths forward
		# when find a subfunc return, mark the path in the subfunc 
		#  (to allow foo: jmp retloc ; bar: jmp retloc retloc: ret to be both recognized as subfuncs 
		#   otherwise when dasm bar, 'retloc' is marked as 'already dasmed' and no subfunc detection takes place)
		targets.zip(targets_found).each { |t, tf|
			if tf
				result |= [tf]
			else
				trace << [20, off, @block[@decoded[off]], @block[@decoded[off]].list.index(di), t]
			end
		}

		if not trace.empty?
			@block[@decoded[orig_off]].backtracked_for |= [orig_off]
		end

		while foo = trace.pop
			depth, off, block, idx, target = foo

			next if depth == 0

			if idx == 0
				block.from.each { |f|
#puts "backtracking : (#{depth}) up to #{'%08x' % f}"
					b = @block[@decoded[f]]
					trace << [depth, f + b.list.last.bin_length, b, b.list.length, target]
					b.backtracked_for |= [orig_off]
				}
			else
				di = block.list[idx-1]
				off -= di.bin_length
#puts "backtracking : eval #{target} in #{di.instruction}"
				target = @cpu.emu_backtrace(di, off, target)
				if t = check_target[target]
#puts " found #{t.inspect}#{' (%08x)' % t if t.kind_of? Integer}"
					result |= [t]
					# TODO
					# mark_as_subfunc(curblock.to) if di.opcode.props[:saveip]
				elsif target and target = target.reduce
#puts " continuing with #{target}"
					# target.reduce is either an Expression or an Indirection, an Integer would have been caught by check_target
					trace << [depth-1, off, block, idx-1, target]
				end
			end
		end

		result
	end
	
	# returns a string (source style) containing the dump of all decoded blocks
	def blocks_to_src
		# array of lines to return
		res = []
		blocks = @block.sort.reverse
		each_section { |edata, baseaddr|
			res << '' << '' << "// section: #{'%08x' % baseaddr} - #{'%08x' % (baseaddr + edata.length)}"
			curaddr = baseaddr
			while curaddr < baseaddr + edata.length
				addr, block = blocks.pop
				if addr and addr >= baseaddr + edata.length
					# block in next section
					blocks << [addr, block]
					addr, block = nil
				end
				addr ||= baseaddr + edata.length	# dump end of section as data
				if addr > curaddr
					# dump data from curaddr to addr
					res.concat data_to_src(edata[curaddr-baseaddr...addr-baseaddr], curaddr)
				end
				curaddr = addr	# may have gone back (overlapping blocks)
				next if not block
				# dump block
				res << ''
				# xrefs
				if not block.from.empty?
					res << "; Xrefs: #{block.from.map { |f| '%08x' % f }.join(', ')}"
				end
				# labels
				edata.export.keys.find_all { |k| edata.export[k] == curaddr - baseaddr }.each { |l| res << "#{l}:" }
				# instrs
				block.list.each { |di|
					binstr = edata.data[curaddr-baseaddr, di.bin_length].unpack('C*').map { |b| '%02x' % b }.join
					res << "  #{di.instruction.to_s.ljust(29)} ; @#{'%08x' % curaddr}   #{binstr}"
					res.last << '  -- ' << di.comment if di.comment
					curaddr += di.bin_length
				}
			end
		}
		res.join("\n")
	end

	# returns an array of strings representing the content of edata as data
	# split on labels
	def data_to_src(edata, base)
		res = []
		return res if not edata
		edata.ptr = 0
		l = ''
		lastoff = nil 
		flush = proc {
			if not l.empty?
				res << l.ljust(56)
				res.last << (' ; %08x' % (lastoff + base)) if lastoff
				l = ''
			end
			lastoff = nil
		}
		rawsize = edata.rawsize
		while edata.ptr < edata.virtsize
			# export
			if edata.export.index(edata.ptr)
				flush[]
				edata.export.keys.find_all { |k| edata.export[k] == edata.ptr }.sort.each { |label| res << "#{label}:" }
			end
			# reloc
			if r = edata.reloc[edata.ptr]
				flush[]
				l << {	:i8  => 'db ', :u8  => 'db ', :a8  => 'db ',
					:i16 => 'dw ', :u16 => 'dw ', :a16 => 'dw ',
					:i32 => 'dd ', :u32 => 'dd ', :a32 => 'dd ',
					:i64 => 'dq ', :u64 => 'dq ', :a64 => 'dq '
				}.fetch(r.type, "db /* unknown data type for #{r.type.inspect} */ ")
				l << r.target.to_s
				flush[]
				edata.ptr += Expression::INT_SIZE[r.type]/8
				next
			end
			flush[] if (base+edata.ptr) % 16 == 0
			if edata.ptr >= rawsize
				flush[]
				len = (edata.export.values.find_all { |k| k > edata.ptr }.min || edata.virtsize) - edata.ptr
				res << ("db #{len} dup(?)".ljust(56) + (' ; %08x' % (base + edata.ptr)))
				edata.ptr += len
			else
				if l.empty?
					lastoff = edata.ptr
					l << 'db '
				end
				c = edata.data[edata.ptr]
				if (0x20..0x7e).include? c and c != ?" and c != ?\\
					# string
					if l[-1] != ?"
						l << ', ' if l.length > 3
						l << '""'
					end
					l[-1, 0] = c.chr
				else
					# any byte
					l << ', ' if l.length > 3
					l << Expression[c].to_s
				end
				edata.ptr += 1
			end
		end
		flush[]
		res
	end
end

class EncodedData
	attr_accessor :ptr
	def get_byte
		@ptr += 1
		if @ptr <= @data.length
			@data[ptr-1]
		elsif @ptr <= @virtsize
			0
		end
	end

	def read(len)
		str = ''
		if @ptr < @data.length
			str << @data[@ptr, len]
		end
		@ptr += len
		str.ljust(len, "\0")
	end
	
	# returns an Expression on relocation, or a Numeric
	def decode_imm(type, endianness)
		if rel = @reloc[@ptr]
			if rel.type == type and rel.endianness == endianness
				@ptr += Expression::INT_SIZE[type]/8
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})"
		end
		Expression.decode_imm(read(Expression::INT_SIZE[type]/8), type, endianness)
	end
end

class Expression
	def self.decode_imm(str, type, endianness)
                val = 0
                case endianness
                when :little : str.reverse
		when :big : str
		end.unpack('C*').each { |b| val = (val << 8) | b }
		val = val - (1 << (INT_SIZE[type])) if type.to_s[0] == ?i and val >> (INT_SIZE[type]-1) == 1	# XXX booh
		val
	end

end
end
