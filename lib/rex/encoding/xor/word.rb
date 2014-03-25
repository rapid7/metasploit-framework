# -*- coding: binary -*-

require 'rex/encoding/xor/generic'

#
# Routine for xor encoding a buffer by a 2-byte (intel word) key.  The perl
# version used to pad this buffer out to a 2-byte boundary, but I can't think
# of a good reason to do that anymore, so this doesn't.
#

module Rex
module Encoding
module Xor

class Word < Generic

  def Word.keysize
    2
  end

end end end end # Word/Xor/Encoding/Rex
