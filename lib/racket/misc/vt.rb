# $Id: vt.rb 14 2008-03-02 05:42:30Z warchild $
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
# Simple class to represent a datastructure that is made up of a 
# null terminted string followed by an arbitrary number of
# arbitrarily sized values, followed by a "rest" field.
class VT 
  # the value for this VT object
  attr_accessor :value
  # the array of types for this VT object
  attr_accessor :types
  # everything else
  attr_accessor :rest

  # Create a new VT which consists of a null terminated string
  # followed by some number of arbitrarily sized values, as 
  # specified by +args+
  def initialize(*args)
    @lengths = args
    @types = []
    @value = ""
  end 

  # Given +data+, return the value and an array
  # of the types as dictated by this instance
  def decode(data)
    null = data.index(0x00)
    value = data.unpack("a#{null}")[0]
    data = data.slice(null+1, data.length)
  
    n = 0
    types = []
    @lengths.each do |l|
      types[n] = data.unpack("#{punpack_string(l)}")[0]
      data = data.slice(l, data.length)
      n += 1
    end

    [value, types, data]
  end

  # Given +data+, set the +value+ and +types+ array
  # accordingly
  def decode!(data)
    @value, @types, @rest = self.decode(data)
  end
  
  # Return a string suitable for use elsewhere
  def encode
    s = "#{@value}\000"

    n = 0
    @lengths.each do |l|
      s << [@types[n]].pack("#{punpack_string(l)}")
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
          raise ArgumentError, "Size #{s} not supported"
      end
    s
  end

end
end
end
# vim: set ts=2 et sw=2:
