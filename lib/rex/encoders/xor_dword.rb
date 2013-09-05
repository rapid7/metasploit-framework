#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/arch/x86'
require 'rex/encoder/xor/dword'

module Rex
module Encoders

###
#
# Spoon's smaller variable-length encoder (updated to use call $+4 by vlad902)
#
###
class XorDword < Rex::Encoder::Xor::Dword
  module Backend
    def _prepend
      # set the counter to the rounded up number of dwords to decode
      Rex::Arch::X86.set(
        Rex::Arch::X86::ECX,
        (encoded.length - 1 >> 2) + 1,
        badchars
      ) +
      "\xe8\xff\xff\xff" +                # call $+4
      "\xff\xc0" +                        # inc eax
      "\x5e" +                            # pop esi
      "\x81\x76\x0e" + key +              # xor_xor: xor [esi + 0x0e], $xorkey
      "\x83\xee\xfc" +                    # sub esi, -4
      "\xe2\xf4"                          # loop xor_xor
    end
  end

  include Backend
end

end end
