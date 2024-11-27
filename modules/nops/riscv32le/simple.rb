##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# This class implements a simple NOP generator for RISC-V 32-bit (Little Endian)
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name' => 'Simple',
      'Alias' => 'riscv32le_simple',
      'Description' => 'Simple NOP generator',
      'License' => MSF_LICENSE,
      'Author' => ['bcoles'],
      'Arch' => ARCH_RISCV32LE)
    register_advanced_options([
      OptBool.new('RandomNops', [false, 'Generate a random NOP sled', true]),
    ])
  end

  def generate_sled(length, opts)
    badchars = opts['BadChars'] || ''
    random = opts['Random'] || datastore['RandomNops']

    nops = [
      # Safe NULL-free nops using temporary registers (t0 - t6)
      [0x400282b3].pack('V'),    # sub t0, t0, 0
      [0x40030333].pack('V'),    # sub t1, t1, 0
      [0x400383b3].pack('V'),    # sub t2, t2, 0
      [0x400e0e33].pack('V'),    # sub t3, t3, 0
      [0x400e8eb3].pack('V'),    # sub t4, t4, 0
      [0x400f0f33].pack('V'),    # sub t5, t5, 0
      [0x400f8fb3].pack('V'),    # sub t6, t6, 0

      # Safe NULL-free nops using zero register (x0)
      [0x01102013].pack('V'),    # slti x0, x0, 0x11
      [0x7ff02013].pack('V'),    # slti x0, x0, 0x7ff

      [0x01103013].pack('V'),    # sltiu x0, x0, 0x11
      [0x7ff03013].pack('V'),    # sltiu x0, x0, 0x7ff

      [0x01105013].pack('V'),    # srli x0, x0, 0x11
      [0x01f05013].pack('V'),    # srli x0, x0, 0x1f

      [0x01101013].pack('V'),    # slli x0, x0, 0x11
      [0x01f01013].pack('V'),    # slli x0, x0, 0x1f

      [0x41105013].pack('V'),    # srai x0, x0, 0x11
      [0x41f05013].pack('V'),    # srai x0, x0, 0x1f

      [0x01106013].pack('V'),    # ori x0, x0, 0x11
      [0x7ff06013].pack('V'),    # ori x0, x0, 0x7ff

      [0x01104013].pack('V'),    # xori x0, x0, 0x11
      [0x7ff04013].pack('V'),    # xori x0, x0, 0x7ff

      [0x01107013].pack('V'),    # andi x0, x0, 0x11
      [0x7ff07013].pack('V'),    # andi x0, x0, 0x7ff

      [0x10101037].pack('V'),    # lui x0, 0x10101
      [0xfffff037].pack('V'),    # lui x0, 0xfffff

      # Safe NULL-free numeric nops using zero register (x0)
      # lui x0, 0x????3037
      "\x37\x30" + Rex::Text.rand_text_numeric(2, badchars),

      # Safe NULL-free alphanumeric nops using zero register (x0)
      # lui x0, 0x????[357]037
      "\x37\x30" + Rex::Text.rand_text_alphanumeric(2, badchars),
      "\x37\x50" + Rex::Text.rand_text_alphanumeric(2, badchars),
      "\x37\x70" + Rex::Text.rand_text_alphanumeric(2, badchars),

      # Safe NULL-free english nops using zero register (x0)
      # lui x0, 0x????[34567]037
      "\x37\x30" + Rex::Text.rand_text_english(2, badchars),
      "\x37\x40" + Rex::Text.rand_text_english(2, badchars),
      "\x37\x50" + Rex::Text.rand_text_english(2, badchars),
      "\x37\x60" + Rex::Text.rand_text_english(2, badchars),
      "\x37\x70" + Rex::Text.rand_text_english(2, badchars),
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
