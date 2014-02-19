#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm/exe_format/shellcode'

class TestEncodedData < Test::Unit::TestCase
	def compile(src)
		p = Metasm::Shellcode.assemble(Metasm::UnknownCPU.new(32, :little), src)
		p.encoded
	end

	def test_basic
		e = compile <<EOS
toto db 42
tutu db 48
dd bla
EOS
		assert_equal(6, e.virtsize)
		assert_equal(2, e.export.keys.length)
		assert_equal(0, e.export['toto'])
		assert_equal(1, e.reloc.keys.length)
		assert_equal('bla', e.reloc[2].target.reduce.rexpr)
	end

	def test_slice
		e = compile <<EOS
db 4 dup(1)
toto:
db 4 dup(2)
db 4 dup(?)
foo:
dd bla
tutu:
EOS
		e1 = e[4, 8]
		e2 = e[4..11]
		e3 = e[4...12]
		e4 = e['toto', 8]
		e5 = e['toto'...'foo']
		assert_equal([e1.data, e1.virtsize], [e2.data, e2.virtsize])
		assert_equal([e1.data, e1.virtsize], [e3.data, e3.virtsize])
		assert_equal([e1.data, e1.virtsize], [e4.data, e4.virtsize])
		assert_equal([e1.data, e1.virtsize], [e5.data, e5.virtsize])
		assert_equal(nil, e[53, 12])
		assert_equal(2, e[2,  2].export['toto'])
		assert_equal(4, e[0,  4].export['toto'])
		assert_equal(1, e[0, 16].reloc.length)
		assert_equal(0, e[0, 15].reloc.length)
		assert_equal(0, e[13, 8].reloc.length)
		assert_equal(1, e[12, 4].reloc.length)
		assert_equal(16, e[0, 50].virtsize)
		assert_equal(1, e[15, 50].virtsize)
		e.align 5
		assert_equal(20, e.virtsize)
		e.align 5
		assert_equal(20, e.virtsize)
		e.fill 30
		assert_equal(30, e.virtsize)
	end

	def test_slice2
		e = compile <<EOS
db '1'
toto:
.pad
tutu:
db '0'
.offset toto+11
EOS
		assert_equal(12, e.virtsize)
		assert_equal(11, e.export['tutu'])
		e[1..10] = 'abcdefghij'
		assert_equal(12, e.virtsize)
		assert_equal(2, e.export.length)
		e[1, 10] = 'jihgfedcba'
		assert_equal(12, e.virtsize)
		e[1...11] = 'abcdefghij'
		assert_equal(12, e.virtsize)
		e.patch('toto', 'tutu', 'xxx')
		assert_equal('1xxxdefghij0', e.data)
		e[1..10] = 'z'
		assert_equal(3, e.virtsize)
		assert_equal(2, e.export['tutu'])
		assert_raise(Metasm::EncodeError) { e.patch('toto', 'tutu', 'toolong') }

		e = compile <<EOS
db '1'
dd rel
db '2'
EOS
		assert_equal(1, e.reloc.length)
		assert_equal(1, e[1, 4].reloc.length)
		assert_equal(1, e[1..4].reloc.length)
		assert_equal(1, e[1...5].reloc.length)
		assert_equal(0, e[2, 8].reloc.length)
		assert_equal(0, e[1, 3].reloc.length)
	end

	def test_fixup
		e = compile <<EOS
db 1
db toto + tata
dd tutu
EOS
		assert_equal(2, e.reloc.length)
		e.fixup!('toto' => 42)
		assert_raise(Metasm::EncodeError) { e.fixup('tata' => 192349129) }
		e.fixup('tata' => -12)
		assert_equal(30.chr[0], e.data[1])
		assert_equal(1, e.reloc.length)
		assert_equal(2, e.offset_of_reloc('tutu'))
		assert_equal(2, e.offset_of_reloc(Metasm::Expression[:+, 'tutu']))
		e.fixup('tutu' => 1024)
		assert_equal("\1\x1e\0\4\0\0", e.data)

		ee = Metasm::Expression[:+, 'bla'].encode(:u16, :big)
		ee.fixup('bla' => 1024)
		assert_equal("\4\0", ee.data)
		
		eee = compile <<EOS
db abc - def
def:
db 12 dup(?, 3 dup('x'))
abc:
EOS
		assert_equal((12*4).chr[0], eee.data[0])
	end
end
