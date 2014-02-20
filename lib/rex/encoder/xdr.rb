# -*- coding: binary -*-
module Rex
module Encoder

###
#
# This class implements basic XDR encoding.
#
###
module XDR
  MAX_ARG = 0xffffffff

  # Also: unsigned int, bool, enum
  def XDR.encode_int(int)
    return [int].pack('N')
  end

  def XDR.decode_int!(data)
      return data.slice!(0..3).unpack('N')[0] if data
      data = 0
  end

  def XDR.encode_lchar(char)
    char |= 0xffffff00 if char & 0x80 != 0
    return encode_int(char)
  end

  def XDR.decode_lchar!(data)
    return (decode_int!(data) & 0xff).chr
  end

  # Also: Variable length opaque
  def XDR.encode_string(str, max=MAX_ARG)
    raise ArgumentError, 'XDR: String too long' if str.length > max
    len = str.length
    str << "\x00" * ((4 - (len & 3)) & 3)
    return encode_int(len) + str
  end

  def XDR.decode_string!(data)
    real_len = decode_int!(data)
    return "" if real_len == 0
    align_len = (real_len + 3) & ~3
    return data.slice!(0..align_len-1).slice(0..real_len-1)
  end

  def XDR.encode_varray(arr, max=MAX_ARG, &block)
    raise ArgumentError, 'XDR: Too many array elements' if arr.length > max
    return encode_int(arr.length) + arr.collect(&block).join(nil)
  end

  def XDR.decode_varray!(data)
    buf = []
    1.upto(decode_int!(data)) { buf.push(yield(data)) }
    return buf
  end

  # encode(0, [0, 1], "foo", ["bar", 4]) does:
  #   encode_int(0) +
  #   encode_varray([0, 1]) { |i| XDR.encode_int(i) } +
  #   encode_string("foo") +
  #   encode_string("bar", 4)
  def XDR.encode(*data)
    data.collect do |var|
      if var.kind_of?(String)
        encode_string(var)
      elsif var.kind_of?(Integer)
        encode_int(var)
      elsif var.kind_of?(Array) && var[0].kind_of?(String)
        raise ArgumentError, 'XDR: Incorrect string array arguments' if var.length != 2
        encode_string(var[0], var[1])
      elsif var.kind_of?(Array) && var[0].kind_of?(Integer)
        encode_varray(var) { |i| XDR.encode_int(i) }
      # 0 means an empty array index in the case of Integer and an empty string in
      #   the case of String so we get the best of both worlds
      elsif var.kind_of?(Array) && var[0].nil?
        encode_int(0)
      else
        type = var.class
        type = var[0].class if var.kind_of?(Array)
        raise TypeError, "XDR: encode does not support #{type}"
      end
    end.join(nil)
  end

# decode(buf, Integer, String, [Integer], [String]) does:
# [decode_int!(buf), decode_string!(buf),
#   decode_varray!(buf) { |i| XDR.decode_int!(i) },
#   decode_varray!(buf) { |s| XDR.decode_string(s) }]
  def XDR.decode!(buf, *data)
    return *data.collect do |var|
      if data.length == 0
      elsif var.kind_of?(Array) && var[0] == String
        decode_varray!(buf) { |s| XDR.decode_string!(s) }
      elsif var.kind_of?(Array) && var[0] == Integer
        decode_varray!(buf) { |i| XDR.decode_int!(i) }
      elsif var == String
        decode_string!(buf)
      elsif var == Integer
        decode_int!(buf)
      end
    end
  end
end

end
end
