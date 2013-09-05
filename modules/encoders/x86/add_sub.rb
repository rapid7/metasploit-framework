##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Encoder

  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Add/Sub Encoder',
      'Description'      => %q{
          Encodes payload with add or sub instructions. This idea came
          from (offensive-security) muts' hp nnm 7.5.1 exploit.
      },
      'Author'           => 'Melih Sarica <ms[at]sevure.com>',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'BlockSize'  => 4
        })
  end

  def add_or_sub(avchars)
    add = [0x05, 0x50, 0x58, 0x25, 0x54, 0x5C]
    sub = [0x2D, 0x50, 0x58, 0x25, 0x54, 0x5C]
    return 1 if add.all?{|ch|avchars.include?ch.chr}
    return 2 if sub.all?{|ch|avchars.include?ch.chr}
    return 0
  end

  def write_inst(inst, mcode)
    @data << inst
    if mcode != 0
      for i in 0...4
        t = mcode & 0x000000FF;
        @data << t
        mcode = mcode >> 8;
      end
    end
  end

  def rand_with_av_chars()
    t2 = 0
    for i in 0...4
      c = @avchars[rand(@avchars.size)].ord.to_i()
      t2 = t2 <<8
      t2 += c
    end
    return t2
  end

  def check_non_av_chars(target)
    for i in 0...4
      t = target & 0x000000FF;
      return true if not @avchars.include?t.chr
      target = target >> 8;
    end
    return false
  end

  def encode_inst(target)
    begin
      a = rand_with_av_chars()
      b = rand_with_av_chars()
      c = target - a - b if @set == 1
      c = 0 - target - a - b if @set == 2
      c = c%(0xFFFFFFFF+1)
    end while check_non_av_chars(c) == true
    write_inst(@inst["opcode"], a)
    write_inst(@inst["opcode"], b)
    write_inst(@inst["opcode"], c)
  end

  def encode_shellcode(target, z1, z2)
    write_inst(@inst["and"], z1);
    write_inst(@inst["and"], z2);
    encode_inst(target);
    write_inst(@inst["push"], 0);
  end

  def decoder_stub(state)
    buf = ""
    shellcode = state.buf.split(//)
    while shellcode.size>0
      buf << shellcode.pop(4).join
    end
    state.buf = buf
    @data = ""
    @avchars = ""
    for i in 0..255
      @avchars = @avchars + i.chr.to_s if not state.badchars.include?i.chr.to_s
    end
    offset = (datastore['BufferOffset'] || 0).to_i
    @inst = {}
    @set = add_or_sub(@avchars)
    if @set == 0 then
      raise RuntimeError, "Bad character list includes essential characters."
      exit
    elsif @set == 1 then #add
      @inst["opcode"] = 0x05
    else #sub
      @inst["opcode"] = 0x2d
    end
    @inst["push"] = 0x50
    @inst["pop"] = 0x58
    @inst["and"] = 0x25
    @inst["push_esp"] = 0x54
    @inst["pop_esp"] = 0x5c
    if state.buf.size%4 != 0 then
      raise RuntimeError, "Shellcode size must be divisible by 4, try nop padding."
      exit
    end
    #init
    write_inst(@inst["push_esp"], 0)
    write_inst(@inst["pop"], 0)
    encode_inst(offset)
    write_inst(@inst["push"], 0)
    write_inst(@inst["pop_esp"], 0)
    #zeroing registers
    begin
      @z1 = rand_with_av_chars()
      @z2 = rand_with_av_chars()
    end while @z1&@z2 != 0
    decoder = @data
    return decoder
  end

  def encode_block(state, block)
    #encoding shellcode
    @data = ""
    target = block.split(//)
    return if target.size<4
    t = 0
    for i in 0..3
      t1 = target[3-i][0].ord.to_i
      t = t<<8
      t = t + t1
    end
    encode_shellcode(t, @z1, @z2);
    encoded = @data
    return encoded
  end
end

