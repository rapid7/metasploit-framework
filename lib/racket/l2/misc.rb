# $Id: misc.rb 142 2009-12-13 01:53:14Z jhart $
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
module L2
  # Miscelaneous L2 helper methods
  module Misc

  # given a string representing a MAC address, return the
  # human readable form
  def Misc.string2mac(string)
    string.unpack("C*").map { |i| i.to_s(16).ljust(2,"0") }.join(":")
  end

  # given a MAC address, return the string representation
  def Misc.mac2string(mac)
    mac.split(":").map { |i| i.hex.chr }.join
  end

  # given a MAC address, return the long representation
  def Misc.mac2long(addr)
    long = 0
    addr.split(':').map { |s| s.to_i(16) }.each do |o|
      long = (long << 8) ^ o
    end
    long
  end

  # given a long representing a MAC address
  # print it out in human readable form of a given length, 
  # defaulting to 6 (ethernet)
  def Misc.long2mac(long, len=6)
    long.to_s(16).rjust(len*2, '0').unpack("a2"*len).join(":")
  end
  
  # Return a random MAC, defaults to 6 bytes (ethernet)
  def Misc.randommac(len=6)
    long2mac(rand(2**(8*len)), len)
  end
end
end
end
# vim: set ts=2 et sw=2:
