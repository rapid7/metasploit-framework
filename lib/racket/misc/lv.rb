# $Id: lv.rb 14 2008-03-02 05:42:30Z warchild $
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
# Simple class to represent data structures that
# consist of an arbitrary number of length value pairs.
class LV
  # An array containing the values parsed from this LV
  attr_accessor :values
  # The lengths of the values parsed from this LV
  attr_accessor :lengths
  # everything else
  attr_accessor :rest

  # Create a new LV object whose L sizes are specified in +args+
  def initialize(*args)
    @sizes = args
    @values = []
    @lengths = []
  end 


  def decode(data)
    n = 0
    values = []
    lengths = []
    @sizes.each do |s|
      # XXX: raise an error here if there is not enough data to
      # unpack this next LV
      lengths[n] = data.unpack("#{punpack_string(s)}")[0]
      data = data.slice(s, data.length)
      values[n] = data.unpack("a#{lengths[n]}")[0]
      data = data.slice(lengths[n], data.length)
      n += 1
    end

    # data now contains "rest"
    [lengths, values, data]
  end
  
  def decode!(data)
    @lengths, @values, @rest = self.decode(data)
  end

  def encode
    n = 0
    s = ""
    @lengths.each do |l|
      s << [l].pack("#{punpack_string(@sizes[n])}")
      s << [@values[n]].pack("a#{l}")
      n += 1
    end
    s
  end

  def to_s
    encode
  end

  def to_str
    encode
  end

private

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
          raise ArgumentError, "Size #{s} not supported"
      end
    s
  end
end
end
end
# vim: set ts=2 et sw=2:
