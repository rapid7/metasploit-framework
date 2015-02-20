# -*- coding: binary -*-
module Msf
module Encoding

###
#
# This class provides basic XOR encoding facilities and is used
# by XOR encoders.
#
###
class Xor

  #
  # Encodes a block using XOR.
  #
  def Xor.encode_block(key, block, block_size = 4, block_pack = 'V')
    offset = 0
    oblock = ''

    while (offset < block.length)
      cblock  = block[offset, block_size].unpack(block_pack)[0]
      cblock ^= key
      oblock += [ cblock ].pack(block_pack)
    end

    return oblock
  end

end

end end
