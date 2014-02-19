#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# This file tries to handle simple self-modifying code patterns
# To be used as a --plugin for a Disassembler object
#

module SMC

# a copy-on-write copy of dasm address space (continuous segment only)
class CoWData
	attr_accessor :startaddr, :data
	def initialize(dasm)
		@dasm = dasm
		@startaddr = 0
		@data = ''
	end

	# return a substring, either from the local cache or from dasm
	# handles overlap
	def [](addr, len)
		if @data.empty?
			s, e = @dasm.get_section_at(addr)
			return if not s
			return s.read(len)
		end
		raddr = addr - @base
		rstart = @startaddr - @base
		if raddr >= rstart and raddr+len <= rstart+@data.length
			@data[0, raddr+len-rstart]
		else
			s, e = @dasm.get_section_at(addr)
			return if not s
			obuf = s.read(len)
			len = obuf.length
			if raddr < rstart and raddr+len > rstart
				olen = [raddr+len-rstart, @data.length].min
				obuf[rstart-raddr, olen] = @data[0, olen]
			elsif raddr < rstart+@data.length and raddr+len > rstart+@data.length
				obuf[0, rstart+@data.length-raddr] = @data[raddr-rstart, rstart+@data.length-raddr]
			end
			obuf
		end
	end

	# set a substring value in the cache
	def []=(addr, len, newdata)
		raise 'len mismatch' if len != newdata.length
		if @data.empty?
			@base = @startaddr = addr
			@data << newdata
			return
		end
		raddr = addr - @base
		rstart = @startaddr - @base
		if raddr+newdata.length < rstart
			s, e = @dasm.get_section_at(addr)
			raise if not s
			obuf = s.read(rstart-(raddr+newdata.length))
			raise if obuf.length != rstart-(raddr+newdata.length)
			newdata += obuf
		elsif raddr > rstart+@data.length
			s, e = @dasm.get_section_at(@startaddr+@data.length)
			raise if not s
			obuf = s.read(raddr-(rstart+@data.length))
			raise if obuf.length != raddr-(rstart+@data.length)
			@data += obuf
		end
		if raddr < rstart
			@data = newdata + @data[raddr+newdata.length-rstart..-1].to_s
			@startaddr = addr
		else
			@data[raddr-rstart, newdata.length] = newdata
		end
	end
end

VirtSections = {}

# try to emulate the byte modifications
# creates a new virtual section in dasm holding decoded data
# adds the virtual section to the dasm, stores the addresses in VirtSections[dasm]
# returns true if successful
def self.emu(dasm, addr)
	puts "emulate SMC @#{Metasm::Expression[addr]}" if $VERBOSE

	writer = nil
	dasm.each_xref(addr, :w) { |xr| writer = xr.origin }
	return if not dasm.di_at(writer)

	a_pre, a_entry, a_cond, a_out, loop_bd = find_loop(dasm, writer)
	return if not a_pre

	# expression checking if we get out of the loop
	loop_again_cond = dasm.cpu.get_jump_condition(dasm.decoded[a_cond])
	loop_again_cond = Expression[:'!', loop_again_cond] if dasm.decoded[a_cond].next_addr != a_out

	init_bd = {}
	loop_bd.keys.grep(Symbol).each { |reg|
		bt = dasm.backtrace(reg, a_pre, :include_start => true)
		init_bd[reg] = bt.first if bt.length == 1 and bt.first != Metasm::Expression::Unknown and bt.first != Metasm::Expression[reg]
	}

	# reject non-determinist memory write
	loop_bd.delete_if { |k, v| k.kind_of? Metasm::Indirection and not dasm.get_section_at(k.pointer.bind(init_bd).reduce) }

	cow_data = CoWData.new(dasm)

	puts "emulation running..." if $VERBOSE
	pre_bd = init_bd
	loop do
		# the effects of the loop
		post_bd = loop_bd.inject({}) { |bd, (k, v)|
	       		if k.kind_of? Metasm::Indirection
				k = k.bind(pre_bd).reduce_rec
				raise "bad ptr #{k}" if not dasm.get_section_at(k.pointer.reduce)
			end
		       	bd.update k => Metasm::Expression[v.bind(pre_bd).reduce]
		}

		# the indirections used by the loop
		# read mem from cow_data
		# ignores stacked indirections & keys
		ind_bd = {}
		post_bd.values.map { |v| v.expr_indirections }.flatten.uniq.each { |ind|
			p = ind.pointer.reduce
			raise "bad loop read #{ind}" if not p.kind_of? Integer
			ind_bd[ind] = Metasm::Expression.decode_imm(cow_data[p, ind.len], "u#{ind.len*8}".to_sym, dasm.cpu.endianness)
		}

		post_bd.each { |k, v|
			next if not k.kind_of? Metasm::Indirection
			cow_data[k.pointer.reduce, k.len] = Metasm::Expression.encode_imm(v.bind(ind_bd).reduce, "u#{k.len*8}".to_sym, dasm.cpu.endianness)
		}

		break if loop_again_cond.bind(post_bd).reduce == 0

		pre_bd = post_bd
		pre_bd.delete_if { |k, v| not k.kind_of? Symbol }
	end

	puts "emulation done (#{cow_data.data.length} bytes)" if $VERBOSE

	VirtSections[dasm] ||= {}
	newbase = "smc#{VirtSections[dasm].length}"
	VirtSections[dasm][addr] = newbase
	dasm.add_section(Metasm::EncodedData.new(cow_data.data), newbase)
	dasm.comment[Metasm::Expression[newbase]] = "SelfModifyingCode from #{dasm.decoded[writer]}"

	true
end

# find the loop containing addr
# only trivial loops handled
# returns [loop start, last instr before loop, loop conditionnal jump, 1st instr after loop, loop binding]
def self.find_loop(dasm, addr)
	b = dasm.decoded[addr].block
	return if not b.to_normal.to_a.include? b.address
	b1 = b2 = b

	pre = (b1.from_normal - [b2.list.last.address]).first
	first = b1.address
	last = b2.list.last.address
	post = (b2.to_normal - [b1.address]).first
	loop_bd = dasm.code_binding(first, post)

	[pre, first, last, post, loop_bd]
end

# redirects the code flow from addr to the decoded section
def self.redirect(dasm, addr)
	return if not VirtSections[dasm] or not newto = Metasm::Expression[VirtSections[dasm][addr]]
	dasm.each_instructionblock { |b|
		next if not b.to_normal.to_a.include? addr
		b.to_normal.map! { |tn| dasm.normalize(tn) == addr ? newto : tn }
		dasm.add_xref(newto, Metasm::Xref.new(:x, b.list.last.address))
		b.list.last.add_comment "x:#{newto}"
		dasm.addrs_todo << [newto, b.list.last.address]
	}
end
end

if self.kind_of? Metasm::Disassembler
# setup the smc callbacks
dasm = self
list = []
dasm.callback_selfmodifying = lambda { |addr| list << addr }
dasm.callback_finished = lambda {
	while addr = list.pop
		SMC.emu(dasm, addr) and SMC.redirect(dasm, addr)
	end
}
end
