##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# MixedNop
# ----------
#
# This class implements a mixed NOP generator for MIPS (big endian)
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'Better',
      'Alias'       => 'mipsbe_better',
      'Description' => 'Better NOP generator',
      'Author'      => 'jm',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_MIPSBE)

    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ])
  end

  def get_register()
      return rand(27) + 1
  end

  def make_bne(reg)
    op = 0x14000000

    reg = get_register()
    offset = rand(65536)

    op = op | ( reg << 21 ) | ( reg << 16 ) | offset
    return op
  end

  def make_or(reg)
    op = 0x00000025

    op = op | ( reg << 21 ) | ( reg << 11 )
    return op
  end

  def make_sll(reg)
    op = 0x00000000

    op = op | ( reg << 16 ) | ( reg << 11 )
    return op
  end

  def make_sra(reg)
    op = 0x00000003

    op = op | ( reg << 16 ) | ( reg << 11 )
    return op
  end

  def make_srl(reg)
    op = 0x00000002

    op = op | ( reg << 16 ) | ( reg << 11 )
    return op
  end

  def make_xori(reg)
    op = 0x38000000

    op = op | ( reg << 21 ) | ( reg << 16 )
    return op
  end

  def make_ori(reg)
    op = 0x34000000

    op = op | ( reg << 21 ) | ( reg << 16 )
    return op
  end

  def generate_sled(length, opts)

    badchars = opts['BadChars'] || ''
    random   = opts['Random']   || datastore['RandomNops']
    nop_fn   = [ :make_bne, :make_or, :make_sll, :make_sra, :make_srl, :make_xori, :make_ori ]
    sled     = ''

    for i in 1..length/4 do
        n = nop_fn.sample
        sled << [send(n, get_register())].pack("N*")
    end

    return sled
  end
end

