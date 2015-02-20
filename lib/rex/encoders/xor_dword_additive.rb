# -*- coding: binary -*-

require 'rex/encoder/xor/dword_additive'

##
#
# Jmp/Call Dword Additive Feedback Encoder
# Author: skape
# Arch:   x86
#
##
module Rex
module Encoders

class XorDwordAdditive < Rex::Encoder::Xor::DwordAdditive
  module Backend

    def _unencoded_transform(data)
      # check for any dword aligned zeros that would falsely terminate the decoder
      idx = 0
      while true
        idx = data.index("\x00\x00\x00\x00", idx)
        break if !idx
        if idx & 3 == 0
          raise RuntimeError, "Unencoded data cannot have a dword aligned 0 dword!", caller()
        end
        idx += 1
      end

      # pad to a dword boundary and append null dword for termination
      data = data + ("\x00" * ((4 - data.length & 3) & 3)) + "\x00\x00\x00\x00"
    end

    def _prepend
      "\xfc"                + # cld
      "\xbb" + key          + # mov ebx, key
      "\xeb\x0c"            + # jmp short 0x14
      "\x5e"                + # pop esi
      "\x56"                + # push esi
      "\x31\x1e"            + # xor [esi], ebx
      "\xad"                + # lodsd
      "\x01\xc3"            + # add ebx, eax
      "\x85\xc0"            + # test eax, eax
      "\x75\xf7"            + # jnz 0xa
      "\xc3"                + # ret
      "\xe8\xef\xff\xff\xff"  # call 0x8
    end
  end

  include Backend
end

end end
