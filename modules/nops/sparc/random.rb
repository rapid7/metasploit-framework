##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# SingleByte
# ----------
#
# This class implements NOP generator for the SPARC platform
#
###
class MetasploitModule < Msf::Nop

  # Nop types
  InsSethi      = 0
  InsArithmetic = 1
  InsBranch     = 2

  # Generator table
  SPARC_Table = [
    [ InsSethi, [ ], ],                       # sethi
    [ InsArithmetic, [ 0, 0 ], ],             # add
    [ InsArithmetic, [ 0, 1 ], ],             # and
    [ InsArithmetic, [ 0, 2 ], ],             # or
    [ InsArithmetic, [ 0, 3 ], ],             # xor
    [ InsArithmetic, [ 0, 4 ], ],             # sub
    [ InsArithmetic, [ 0, 5 ], ],             # andn
    [ InsArithmetic, [ 0, 6 ], ],             # orn
    [ InsArithmetic, [ 0, 7 ], ],             # xnor
    [ InsArithmetic, [ 0, 8 ], ],             # addx
    [ InsArithmetic, [ 0, 12 ], ],            # subx
    [ InsArithmetic, [ 0, 16 ], ],            # addcc
    [ InsArithmetic, [ 0, 17 ], ],            # andcc
    [ InsArithmetic, [ 0, 18 ], ],            # orcc
    [ InsArithmetic, [ 0, 19 ], ],            # xorcc
    [ InsArithmetic, [ 0, 20 ], ],            # subcc
    [ InsArithmetic, [ 0, 21 ], ],            # andncc
    [ InsArithmetic, [ 0, 22 ], ],            # orncc
    [ InsArithmetic, [ 0, 23 ], ],            # xnorcc
    [ InsArithmetic, [ 0, 24 ], ],            # addxcc
    [ InsArithmetic, [ 0, 28 ], ],            # subxcc
    [ InsArithmetic, [ 0, 32 ], ],            # taddcc
    [ InsArithmetic, [ 0, 33 ], ],            # tsubcc
    [ InsArithmetic, [ 0, 36 ], ],            # mulscc
    [ InsArithmetic, [ 2, 37 ], ],            # sll
    [ InsArithmetic, [ 2, 38 ], ],            # srl
    [ InsArithmetic, [ 2, 39 ], ],            # sra
    [ InsArithmetic, [ 4, 40 ], ],            # rdy
    [ InsArithmetic, [ 3, 48 ], ],            # wry
    [ InsBranch, [ 0 ] ],                     # bn[,a]
    [ InsBranch, [ 1 ] ],                     # be[,a]
    [ InsBranch, [ 2 ] ],                     # ble[,a]
    [ InsBranch, [ 3 ] ],                     # bl[,a]
    [ InsBranch, [ 4 ] ],                     # bleu[,a]
    [ InsBranch, [ 5 ] ],                     # bcs[,a]
    [ InsBranch, [ 6 ] ],                     # bneg[,a]
    [ InsBranch, [ 7 ] ],                     # bvs[,a]
    [ InsBranch, [ 8 ] ],                     # ba[,a]
    [ InsBranch, [ 9 ] ],                     # bne[,a]
    [ InsBranch, [ 10 ] ],                    # bg[,a]
    [ InsBranch, [ 11 ] ],                    # bge[,a]
    [ InsBranch, [ 12 ] ],                    # bgu[,a]
    [ InsBranch, [ 13 ] ],                    # bcc[,a]
    [ InsBranch, [ 14 ] ],                    # bpos[,a]
    [ InsBranch, [ 15 ] ],                    # bvc[,a]
  ]

  def initialize
    super(
      'Name'        => 'SPARC NOP Generator',
      'Alias'       => 'sparc_simple',
      'Description' => 'SPARC NOP generator',
      'Author'      => 'vlad902',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_SPARC)

    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ])
  end



  # Nops are always random...
  def generate_sled(length, opts)

    badchars = opts['BadChars'] || ''
    random   = opts['Random']   || datastore['RandomNops']
    blen     = length

    buff  = ''
    count = 0
    while (buff.length < blen)
      r = SPARC_Table[ rand(SPARC_Table.length) ]
      t = ''

      case r[0]
        when InsSethi
          t = ins_sethi(r[1], blen - buff.length)
        when InsArithmetic
          t = ins_arithmetic(r[1], blen - buff.length)
        when InsBranch
          t = ins_branch(r[1], blen - buff.length)
        else
          print_status("Invalid opcode type")
          raise RuntimeError
      end

      failed = false

      t.each_byte do |c|
        failed = true if badchars.include?(c.chr)
      end

      if (not failed)
        buff << t
        count = -100
      end

      if (count > length + 1000)
        if(buff.length != 0)
          return buff.slice(0, 4) * (blen / 4)
        end
        print_status("The SPARC nop generator could not create a usable sled")
        raise RuntimeError
      end

      count += 1
    end

    return buff
  end

  def get_dst_reg
    reg = rand(30).to_i
    reg += 1 if (reg >= 14)		# %sp
    reg += 1 if (reg >= 30)		# %fp
    return reg
  end

  def get_src_reg
    return rand(32).to_i
  end

  def ins_sethi(ref, len=0)
    [(get_dst_reg() << 25) | (4 << 22) | rand(1 << 22)].pack('N')
  end

  def ins_arithmetic(ref, len=0)
    dst = get_dst_reg()
    ver = ref[0]

    # WRY fixups
    if (ver == 3)
      dst = 0
      ver = 1
    end

    # 0, ~1, !2, ~3, !4
    # Use one src reg with a signed 13-bit immediate (non-0)
    if((ver == 0 && rand(2)) || ver == 1)
      return [
        (2 << 30)               |
        (dst << 25)             |
        (ref[1] << 19)          |
        (get_src_reg() << 14)   |
        (1 << 13)               |
        (rand((1 << 13) - 1) + 1)
      ].pack('N')
    end

    # ref[1] could be replaced with a static value since this only encodes for one function but it's done this way for
    # conistancy/clarity.
    if (ver == 4)
      return [(2 << 30) | (dst << 25) | (ref[1] << 19)].pack('N')
    end

    # Use two src regs
    return [
      (2 << 30) |
      (dst << 25) |
      (ref[1] << 19) |
      (get_src_reg() << 14) |
      get_src_reg()
    ].pack('N')
  end

  def ins_branch(ref, len)
    # We jump to 1 instruction before the payload so in cases where the delay slot is another branch instruction that is
    # not taken with the anull bit set the first bit of the payload is not anulled.
    len = (len / 4) - 1

    return '' if len == 0
    len = 0x3fffff if (len >= 0x400000)

    a = rand(2).floor
    b = ref[0]
    c = rand(len - 1).floor

    return [
      (a << 29)  |
      (b << 25)  |
      (2 << 22)  |
      c + 1
    ].pack('N')
  end
end
