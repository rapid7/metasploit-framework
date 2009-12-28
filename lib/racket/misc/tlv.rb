# $Id: tlv.rb 14 2008-03-02 05:42:30Z warchild $
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
module Misc
# Simple class for your average type, length, value datastructure.
# Everything after the TLV is stuff into +rest+
class TLV
  attr_accessor :type, :length, :value, :rest, :lbytes, :tlinclude

  # Create a new TLV which requires +ts+ bytes for the type field
  # and +ls+ bytes for the length field, where (optionally) the value
  # in +length+ is a multiple of +lbytes+ and (optionally) whether or not
  # the length field indicates the total length of the TLV of just that of 
  # the value
  def initialize(ts, ls, lbytes=1, tlinclude=false)
    @ts = ts
    @ls = ls
    @lbytes = lbytes
    @tlinclude = tlinclude
  end 

  # Given +data+, return the type, length, value and rest 
  # values as dictated by this instance.
  def decode(data)
    s = "#{punpack_string(@ts)}#{punpack_string(@ls)}"
    type, length, tmp = data.unpack("#{s}a*")
    if (type.nil? or length.nil?)
      nil
    else
      elength = (length * lbytes) - (@tlinclude ? (@ls + @ts) : 0) 
      value, rest = tmp.unpack("a#{elength}a*")
      if (value.empty? and length > 0)
        nil
      else
        [type, length, value, rest]
      end
    end
  end

  def decode!(data)
    @type, @length, @value, @rest = self.decode(data)
  end

  # Return a string suitable for use elswhere.
  def encode
    s = "#{punpack_string(@ts)}#{punpack_string(@ls)}"
    [@type, @length, @value].pack("#{s}a*")
  end

  def to_s
    encode
  end

  def to_str
    encode
  end

private
  # XXX: make this handle arbitrarily sized fields
  def punpack_string(size)
    s = ""
    case size
        when 1
          s << "C"
        when 2
          s << "n"
        when 4
          s << "N"
        else
         raise ArgumentError, "Size #{s} is not a supported conversion size"
      end
    s
  end
  
end
end
end
# vim: set ts=2 et sw=2:
