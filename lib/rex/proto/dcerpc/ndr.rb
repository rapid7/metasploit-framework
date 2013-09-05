# -*- coding: binary -*-
require "rex/text"

module Rex
module Proto
module DCERPC
class NDR


  # Provide padding to align the string to the 32bit boundary
  def self.align(string)
    warn 'should be using Rex::Encoder::NDR'
    return "\x00" * ((4 - (string.length & 3)) & 3)
  end

  # Encode a 4 byte long
  # use to encode:
  #       long element_1;
  def self.long(string)
    warn 'should be using Rex::Encoder::NDR'
    return [string].pack('V')
  end

  # Encode a 2 byte short
  # use to encode:
  #       short element_1;
  def self.short(string)
    warn 'should be using Rex::Encoder::NDR'
    return [string].pack('v')
  end

  # Encode a single byte
  # use to encode:
  #       byte element_1;
  def self.byte(string)
    warn 'should be using Rex::Encoder::NDR'
    return [string].pack('c')
  end

  # Encode a byte array
  # use to encode:
  #       char  element_1
  def self.UniConformantArray(string)
    warn 'should be using Rex::Encoder::NDR'
    return long(string.length) + string + align(string)
  end

  # Encode a string
  # use to encode:
  #       w_char *element_1;
  def self.UnicodeConformantVaryingString(string)
    warn 'should be using Rex::Encoder::NDR'
    string += "\x00" # null pad
    return long(string.length) + long(0) + long(string.length) + Rex::Text.to_unicode(string) + align(Rex::Text.to_unicode(string))
  end

  # Encode a string that is already unicode encoded
  # use to encode:
  #       w_char *element_1;
  def self.UnicodeConformantVaryingStringPreBuilt(string)
    warn 'should be using Rex::Encoder::NDR'
    # if the string len is odd, thats bad!
    if string.length % 2 > 0
      string += "\x00"
    end
    len = string.length / 2;
    return long(len) + long(0) + long(len) + string + align(string)
  end

end
end
end
end
