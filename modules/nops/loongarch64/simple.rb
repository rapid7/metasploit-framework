##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# This class implements a simple NOP generator for LoongArch 64-bit (Little Endian)
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name' => 'Simple',
      'Alias' => 'loongarch64_simple',
      'Description' => 'Simple NOP generator',
      'License' => MSF_LICENSE,
      'Author' => ['bcoles'],
      'Arch' => ARCH_LOONGARCH64)
    register_advanced_options([
      OptBool.new('RandomNops', [false, 'Generate a random NOP sled', true]),
    ])
  end

  def generate_sled(length, opts)
    badchars = opts['BadChars'] || ''
    random = opts['Random'] || datastore['RandomNops']

    # Safe NULL-free nops using general purpose registers ($r12 - $r31)
    # All instructions are NULL-free from the base ISA,
    # excluding optional extensions (FPU, LSX, LASX, ...)
    nops = [
      [0x03c0018c].pack('V'),    # xori $t0, $t0, 0
      [0x03c001ad].pack('V'),    # xori $t1, $t1, 0
      [0x03c001ce].pack('V'),    # xori $t2, $t2, 0
      [0x03c001ef].pack('V'),    # xori $t3, $t3, 0
      [0x03c00210].pack('V'),    # xori $t4, $t4, 0
      [0x03c00231].pack('V'),    # xori $t5, $t5, 0
      [0x03c00252].pack('V'),    # xori $t6, $t6, 0
      [0x03c00273].pack('V'),    # xori $t7, $t7, 0
      [0x03c00294].pack('V'),    # xori $t8, $t8, 0
      [0x03c002b5].pack('V'),    # xori $r21, $r21, 0
      [0x03c002d6].pack('V'),    # xori $fp, $fp, 0
      [0x03c002f7].pack('V'),    # xori $s0, $s0, 0
      [0x03c00318].pack('V'),    # xori $s1, $s1, 0
      [0x03c00339].pack('V'),    # xori $s2, $s2, 0
      [0x03c0035a].pack('V'),    # xori $s3, $s3, 0
      [0x03c0037b].pack('V'),    # xori $s4, $s4, 0
      [0x03c0039c].pack('V'),    # xori $s5, $s5, 0
      [0x03c003bd].pack('V'),    # xori $s6, $s6, 0
      [0x03c003de].pack('V'),    # xori $s7, $s7, 0
      [0x03c003ff].pack('V'),    # xori $s8, $s8, 0

      [0x0380018c].pack('V'),    # ori $t0, $t0, 0
      [0x038001ad].pack('V'),    # ori $t1, $t1, 0
      [0x038001ce].pack('V'),    # ori $t2, $t2, 0
      [0x038001ef].pack('V'),    # ori $t3, $t3, 0
      [0x03800210].pack('V'),    # ori $t4, $t4, 0
      [0x03800231].pack('V'),    # ori $t5, $t5, 0
      [0x03800252].pack('V'),    # ori $t6, $t6, 0
      [0x03800273].pack('V'),    # ori $t7, $t7, 0
      [0x03800294].pack('V'),    # ori $t8, $t8, 0
      [0x038002b5].pack('V'),    # ori $r21, $r21, 0
      [0x038002d6].pack('V'),    # ori $fp, $fp, 0
      [0x038002f7].pack('V'),    # ori $s0, $s0, 0
      [0x03800318].pack('V'),    # ori $s1, $s1, 0
      [0x03800339].pack('V'),    # ori $s2, $s2, 0
      [0x0380035a].pack('V'),    # ori $s3, $s3, 0
      [0x0380037b].pack('V'),    # ori $s4, $s4, 0
      [0x0380039c].pack('V'),    # ori $s5, $s5, 0
      [0x038003bd].pack('V'),    # ori $s6, $s6, 0
      [0x038003de].pack('V'),    # ori $s7, $s7, 0
      [0x038003ff].pack('V'),    # ori $s8, $s8, 0

      [0x02c0018c].pack('V'),    # addi.d $t0, $t0, 0
      [0x02c001ad].pack('V'),    # addi.d $t1, $t1, 0
      [0x02c001ce].pack('V'),    # addi.d $t2, $t2, 0
      [0x02c001ef].pack('V'),    # addi.d $t3, $t3, 0
      [0x02c00210].pack('V'),    # addi.d $t4, $t4, 0
      [0x02c00231].pack('V'),    # addi.d $t5, $t5, 0
      [0x02c00252].pack('V'),    # addi.d $t6, $t6, 0
      [0x02c00273].pack('V'),    # addi.d $t7, $t7, 0
      [0x02c00294].pack('V'),    # addi.d $t8, $t8, 0
      [0x02c002b5].pack('V'),    # addi.d $r21, $r21, 0
      [0x02c002d6].pack('V'),    # addi.d $fp, $fp, 0
      [0x02c002f7].pack('V'),    # addi.d $s0, $s0, 0
      [0x02c00318].pack('V'),    # addi.d $s1, $s1, 0
      [0x02c00339].pack('V'),    # addi.d $s2, $s2, 0
      [0x02c0035a].pack('V'),    # addi.d $s3, $s3, 0
      [0x02c0037b].pack('V'),    # addi.d $s4, $s4, 0
      [0x02c0039c].pack('V'),    # addi.d $s5, $s5, 0
      [0x02c003bd].pack('V'),    # addi.d $s6, $s6, 0
      [0x02c003de].pack('V'),    # addi.d $s7, $s7, 0
      [0x02c003ff].pack('V'),    # addi.d $s8, $s8, 0

      [0x0280018c].pack('V'),    # addi.w $t0, $t0, 0
      [0x028001ad].pack('V'),    # addi.w $t1, $t1, 0
      [0x028001ce].pack('V'),    # addi.w $t2, $t2, 0
      [0x028001ef].pack('V'),    # addi.w $t3, $t3, 0
      [0x02800210].pack('V'),    # addi.w $t4, $t4, 0
      [0x02800231].pack('V'),    # addi.w $t5, $t5, 0
      [0x02800252].pack('V'),    # addi.w $t6, $t6, 0
      [0x02800273].pack('V'),    # addi.w $t7, $t7, 0
      [0x02800294].pack('V'),    # addi.w $t8, $t8, 0
      [0x028002b5].pack('V'),    # addi.w $r21, $r21, 0
      [0x028002d6].pack('V'),    # addi.w $fp, $fp, 0
      [0x028002f7].pack('V'),    # addi.w $s0, $s0, 0
      [0x02800318].pack('V'),    # addi.w $s1, $s1, 0
      [0x02800339].pack('V'),    # addi.w $s2, $s2, 0
      [0x0280035a].pack('V'),    # addi.w $s3, $s3, 0
      [0x0280037b].pack('V'),    # addi.w $s4, $s4, 0
      [0x0280039c].pack('V'),    # addi.w $s5, $s5, 0
      [0x028003bd].pack('V'),    # addi.w $s6, $s6, 0
      [0x028003de].pack('V'),    # addi.w $s7, $s7, 0
      [0x028003ff].pack('V'),    # addi.w $s8, $s8, 0
    ]

    # Remove nops containing BadChars
    nops.delete_if do |nop|
      nop.bytes.any? { |byte| badchars.force_encoding('BINARY').include?(byte.chr) }
    end

    # Give up if no safe nops are available
    return if nops.empty?

    # Use random instructions for all NOPs
    if random
      sled = ''
      (length / 4).times do
        sled << nops.sample
      end
      return sled
    end

    # Use a single instruction for all NOPs
    return (nops.sample * (length / 4))
  end
end
