#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/z80/main'

module Metasm

class Z80
  def addop(name, bin, *args)
    o = Opcode.new name, bin
    args.each { |a|
      o.args << a if @fields_mask[a] or @valid_args[a]
      o.props[a] = true if @valid_props[a]
      o.fields[a] = [bin.length-1, @fields_shift[a]] if @fields_mask[a]
      raise "wtf #{a.inspect}" unless @valid_args[a] or @valid_props[a] or @fields_mask[a]
    }
    @opcode_list << o
  end

  def addop_macrocc(name, bin, *args)
    %w[nz z nc c po pe p m].each_with_index { |cc, i|
      dbin = bin.dup
      dbin[0] |= i << 3
      addop name + cc, dbin, *args
    }
  end

  # data from http://www.z80.info/decoding.htm
  def init_z80_common
    @opcode_list = []
    @valid_args.update [:i8, :u8, :i16, :u16, :m16,
      :r_a, :r_af, :r_hl, :r_de, :r_sp, :r_i,
      :m_bc, :m_de, :m_sp, :m_hl, :mf8, :mfc
    ].inject({}) { |h, v| h.update v => true }
    @fields_mask.update :rz => 7, :ry => 7, :rp => 3, :rp2 => 3, :iy => 7, :iy8 => 7
    @fields_shift.update :rz => 0, :ry => 3, :rp => 4, :rp2 => 4, :iy => 3, :iy8 => 3

    # some opcodes are in init_z80 when they are not part of the GB ABI
    addop 'nop',  [0b00_000_000]
    addop 'jr',   [0b00_011_000], :setip, :stopexec, :i8
    %w[nz z nc c].each_with_index { |cc, i|
      addop 'jr' + cc, [0b00_100_000 | (i << 3)], :setip, :i8
    }
    addop 'ld',   [0b00_000_001], :rp, :i16
    addop 'add',  [0b00_001_001], :r_hl, :rp

    addop 'ld',   [0b00_000_010], :m_bc, :r_a
    addop 'ld',   [0b00_001_010], :r_a, :m_bc
    addop 'ld',   [0b00_010_010], :m_de, :r_a
    addop 'ld',   [0b00_011_010], :r_a, :m_de

    addop 'inc',  [0b00_000_011], :rp
    addop 'dec',  [0b00_001_011], :rp
    addop 'inc',  [0b00_000_100], :ry
    addop 'dec',  [0b00_000_101], :ry
    addop 'ld',   [0b00_000_110], :ry, :i8

    addop 'rlca', [0b00_000_111]	# rotate
    addop 'rrca', [0b00_001_111]
    addop 'rla',  [0b00_010_111]
    addop 'rra',  [0b00_011_111]

    addop 'daa',  [0b00_100_111]
    addop 'cpl',  [0b00_101_111]
    addop 'scf',  [0b00_110_111]
    addop 'ccf',  [0b00_111_111]

    addop 'halt', [0b01_110_110]	# ld (HL), (HL)
    addop 'ld',   [0b01_000_000], :ry, :rz

    addop 'add',  [0b10_000_000], :r_a, :rz
    addop 'adc',  [0b10_001_000], :r_a, :rz
    addop 'sub',  [0b10_010_000], :r_a, :rz
    addop 'sbc',  [0b10_011_000], :r_a, :rz
    addop 'and',  [0b10_100_000], :r_a, :rz
    addop 'xor',  [0b10_101_000], :r_a, :rz
    addop 'or',   [0b10_110_000], :r_a, :rz
    addop 'cmp',  [0b10_111_000], :r_a, :rz	# alias cp
    addop 'cp',   [0b10_111_000], :r_a, :rz	# compare

    addop_macrocc 'ret', [0b11_000_000], :setip
    addop 'pop',  [0b11_000_001], :rp2
    addop 'ret',  [0b11_001_001], :stopexec, :setip
    addop 'jmp',  [0b11_101_001], :r_hl, :setip, :stopexec	# alias jp
    addop 'jp',   [0b11_101_001], :r_hl, :setip, :stopexec
    addop 'ld',   [0b11_111_001], :r_sp, :r_hl
    addop_macrocc 'j',  [0b11_000_010], :setip, :u16	# alias jp
    addop_macrocc 'jp', [0b11_000_010], :setip, :u16
    addop 'jmp',  [0b11_000_011], :setip, :stopexec, :u16	# alias jp
    addop 'jp',   [0b11_000_011], :setip, :stopexec, :u16

    addop 'di',   [0b11_110_011]				# disable interrupts
    addop 'ei',   [0b11_111_011]
    addop_macrocc 'call', [0b11_000_100], :u16, :setip, :saveip
    addop 'push', [0b11_000_101], :rp2
    addop 'call', [0b11_001_101], :u16, :setip, :saveip, :stopexec

    addop 'add',  [0b11_000_110], :r_a, :i8
    addop 'adc',  [0b11_001_110], :r_a, :i8
    addop 'sub',  [0b11_010_110], :r_a, :i8
    addop 'sbc',  [0b11_011_110], :r_a, :i8
    addop 'and',  [0b11_100_110], :r_a, :i8
    addop 'xor',  [0b11_101_110], :r_a, :i8
    addop 'or',   [0b11_110_110], :r_a, :i8
    addop 'cp',   [0b11_111_110], :r_a, :i8

    addop 'rst',  [0b11_000_111], :iy8		# call off in page 0

    addop 'rlc',  [0xCB, 0b00_000_000], :rz		# rotate
    addop 'rrc',  [0xCB, 0b00_001_000], :rz
    addop 'rl',   [0xCB, 0b00_010_000], :rz
    addop 'rr',   [0xCB, 0b00_011_000], :rz
    addop 'sla',  [0xCB, 0b00_100_000], :rz		# shift
    addop 'sra',  [0xCB, 0b00_101_000], :rz
    addop 'srl',  [0xCB, 0b00_111_000], :rz
    addop 'bit',  [0xCB, 0b01_000_000], :iy, :rz	# bit test
    addop 'res',  [0xCB, 0b10_000_000], :iy, :rz	# bit reset
    addop 'set',  [0xCB, 0b11_000_000], :iy, :rz	# bit set
  end

  # standard z80
  def init_z80
    init_z80_common

    addop 'ex',   [0b00_001_000], :r_af		# XXX really ex AF, AF' ...
    addop 'djnz', [0b00_010_000], :setip, :i8

    addop 'ld',   [0b00_100_010], :m16, :r_hl
    addop 'ld',   [0b00_101_010], :r_hl, :m16
    addop 'ld',   [0b00_110_010], :m16, :r_a
    addop 'ld',   [0b00_111_010], :r_a, :m16

    addop 'exx',  [0b11_011_001]
    addop 'out',  [0b11_010_011], :i8, :r_a
    addop 'in',   [0b11_011_011], :r_a, :i8

    addop 'ex',   [0b11_100_011], :m_sp, :r_hl
    addop 'ex',   [0b11_101_011], :r_de, :r_hl

    addop 'sll',  [0xCB, 0b00_110_000], :rz

    addop 'in',   [0xED, 0b01_110_000], :u16
    addop 'in',   [0xED, 0b01_000_000], :ry, :u16
    addop 'out',  [0xED, 0b01_110_001], :u16
    addop 'out',  [0xED, 0b01_000_001], :u16, :ry
    addop 'sbc',  [0xED, 0b01_000_010], :r_hl, :rp
    addop 'adc',  [0xED, 0b01_001_010], :r_hl, :rp
    addop 'ld',   [0xED, 0b01_000_011], :m16, :rp
    addop 'ld',   [0xED, 0b01_001_011], :rp, :m16
    addop 'neg',  [0xED, 0b01_000_100], :r_a, :iy	# dummy int field
    addop 'retn', [0xED, 0b01_000_101], :stopexec	# dummy int != 1 ? (1 = reti)
    addop 'reti', [0xED, 0b01_001_101], :stopexec, :setip
    addop 'im',   [0xED, 0b01_000_110], :iy
    addop 'ld',   [0xED, 0b01_000_111], :r_i, :r_a
    addop 'ld',   [0xED, 0b01_001_111], :r_r, :r_a
    addop 'ld',   [0xED, 0b01_010_111], :r_a, :r_i
    addop 'ld',   [0xED, 0b01_011_111], :r_a, :r_r
    addop 'rrd',  [0xED, 0b01_100_111]
    addop 'rld',  [0xED, 0b01_101_111]

    addop 'ldi',  [0xED, 0b10_100_000]
    addop 'ldd',  [0xED, 0b10_101_000]
    addop 'ldir', [0xED, 0b10_110_000]
    addop 'lddr', [0xED, 0b10_111_000]
    addop 'cpi',  [0xED, 0b10_100_001]
    addop 'cpd',  [0xED, 0b10_101_001]
    addop 'cpir', [0xED, 0b10_110_001]
    addop 'cpdr', [0xED, 0b10_111_001]
    addop 'ini',  [0xED, 0b10_100_010]
    addop 'ind',  [0xED, 0b10_101_010]
    addop 'inir', [0xED, 0b10_110_010]
    addop 'indr', [0xED, 0b10_111_010]
    addop 'outi', [0xED, 0b10_100_011]
    addop 'outd', [0xED, 0b10_101_011]
    addop 'otir', [0xED, 0b10_110_011]
    addop 'otdr', [0xED, 0b10_111_011]

    addop 'unk_ed', [0xED], :i8

    addop 'unk_nop', [], :i8	# undefined opcode = nop
    @unknown_opcode = @opcode_list.last
  end

  # gameboy processor
  # from http://nocash.emubase.de/pandocs.htm#cpucomparisionwithz80
  def init_gb
    init_z80_common

    addop 'ld',   [0x08], :m16, :r_sp
    addop 'stop', [0x10]

    addop 'ldi',  [0x22], :m_hl, :r_a	# (hl++) <- a
    addop 'ldi',  [0x2A], :r_a, :m_hl
    addop 'ldd',  [0x32], :m_hl, :r_a	# (hl--) <- a
    addop 'ldd',  [0x3A], :r_a, :m_hl

    addop 'reti', [0xD9], :setip, :stopexec

    # override retpo/jpo
    @opcode_list.delete_if { |op| op.bin[0] & 0xE5 == 0xE0 }	# rm E0 E2 E8 EA F0 F2 F8 FA
    addop 'ld',  [0xE0], :mf8, :r_a	# (0xff00 + :i8)
    addop 'ld',  [0xE2], :mfc, :r_a	# (0xff00 + :r_c)
    addop 'add', [0xE8], :r_sp, :i8
    addop 'ld',  [0xEA], :m16, :r_a
    addop 'ld',  [0xF0], :r_a, :mf8
    addop 'ld',  [0xF2], :r_a, :mfc
    addop 'ld',  [0xF8], :r_hl, :r_sp, :i8	# hl <- sp+:i8
    addop 'ld',  [0xFA], :r_a, :m16

    addop 'swap', [0xCB, 0x30], :rz

    addop 'inv_dd', [0xDD], :stopexec	# invalid prefixes
    addop 'inv_ed', [0xED], :stopexec
    addop 'inv_fd', [0xFD], :stopexec

    addop 'unk_nop', [], :i8	# undefined opcode = nop
    @unknown_opcode = @opcode_list.last
  end

  alias init_latest init_z80
end
end
