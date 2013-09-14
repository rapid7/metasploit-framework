##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


###
#
# SingleByte
# ----------
#
# This class implements simple NOP generator for PowerPC
#
###
class Metasploit3 < Msf::Nop


  def initialize
    super(
      'Name'        => 'Simple',
      'Alias'       => 'ppc_simple',
      'Description' => 'Simple NOP generator',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_PPC)

    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ], self.class)
  end


  def generate_sled(length, opts)

    badchars = opts['BadChars'] || ''
    random   = opts['Random']   || datastore['RandomNops']

    if( random and random.match(/^(t|y|1)/i) )
      1.upto(1024) do |i|
        regs_d = (rand(0x8000 - 0x0800) + 0x0800).to_i
        regs_b = [regs_d].pack('n').unpack('B*')[0][1, 15]
        flag_o = rand(2).to_i
        flag_r = rand(2).to_i

        pcword = ["011111#{regs_b}#{flag_o}100001010#{flag_r}"].pack("B*")
        failed = false

        pcword.each_byte do |c|
          failed = true if badchars.include?(c.chr)
        end

        next if failed

        return (pcword * (length / 4))[0, length]
      end
    end

    return ("\x60" * length)[0, length]
  end

end
