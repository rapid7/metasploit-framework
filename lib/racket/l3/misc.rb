# $Id: misc.rb 14 2008-03-02 05:42:30Z warchild $
#
# Copyright (c) 2008, Jon Hart 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY Jon Hart ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Jon Hart BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
module Racket
module L3
  module Misc
    # given an IPv4 address packed as an integer
    # return the friendly "dotted quad"
    def Misc.long2ipv4(long)
      quad = Array.new(4)
      quad[0] = (long >> 24) & 255
      quad[1] = (long >> 16) & 255
      quad[2] = (long >> 8 ) & 255
      quad[3] = long & 255
      quad.join(".")
    end

    def Misc.long2ipv6(long)
    end

    # given a "dotted quad" representing an IPv4
    # address, return the integer representation
    def Misc.ipv42long(ip)
      quad = ip.split(/\./)
      quad.collect! {|s| s.to_i}
      # XXX: replace this with an inject
      quad[3] + (256 * quad[2]) + ((256**2) * quad[1]) + ((256**3) * quad[0])
    end

    # Calculate the checksum.  16 bit one's complement of the one's
    # complement sum of all 16 bit words
    def Misc.checksum(data)
      num_shorts = data.length / 2
      csum = 0
      count = data.length
      
      data.unpack("S#{num_shorts}").each { |x|
        csum += x
        count -= 2
      }

      if (count == 1)
        csum += data[data.length - 1]
      end

      csum = (csum >> 16) + (csum & 0xffff)
      csum = ~((csum >> 16) + csum) & 0xffff
      ([csum].pack("S*")).unpack("n*")[0]
    end
  end
end
end
# vim: set ts=2 et sw=2:
