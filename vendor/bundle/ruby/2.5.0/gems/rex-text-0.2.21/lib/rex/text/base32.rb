# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Base32 code
    #

    # Based on --> https://github.com/stesla/base32

    # Copyright (c) 2007-2011 Samuel Tesla

    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:

    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.

    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    # THE SOFTWARE.


    #
    # Base32 encoder
    #
    def self.b32encode(bytes_in)
      n = (bytes_in.length * 8.0 / 5.0).ceil
      p = n < 8 ? 5 - (bytes_in.length * 8) % 5 : 0
      c = bytes_in.inject(0) {|m,o| (m << 8) + o} << p
      [(0..n-1).to_a.reverse.collect {|i| Base32[(c >> i * 5) & 0x1f].chr},
       ("=" * (8-n))]
    end

    def self.encode_base32(str)
      bytes = str.bytes
      result = ''
      size= 5
      while bytes.any? do
        bytes.each_slice(size) do |a|
          bytes_out = b32encode(a).flatten.join
          result << bytes_out
          bytes = bytes.drop(size)
        end
      end
      return result
    end

    #
    # Base32 decoder
    #
    def self.b32decode(bytes_in)
      bytes = bytes_in.take_while {|c| c != 61} # strip padding
      n = (bytes.length * 5.0 / 8.0).floor
      p = bytes.length < 8 ? 5 - (n * 8) % 5 : 0
      c = bytes.inject(0) {|m,o| (m << 5) + Base32.index(o.chr)} >> p
      (0..n-1).to_a.reverse.collect {|i| ((c >> i * 8) & 0xff).chr}
    end

    def self.decode_base32(str)
      bytes = str.bytes
      result = ''
      size= 8
      while bytes.any? do
        bytes.each_slice(size) do |a|
          bytes_out = b32decode(a).flatten.join
          result << bytes_out
          bytes = bytes.drop(size)
        end
      end
      return result
    end

  end
end
