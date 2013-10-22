# -*- coding: binary -*-
require "rex/text"

module Rex
module Encoder
module NDR

  # Provide padding to align the string to the 32bit boundary
  def NDR.align(string)
    return "\x00" * ((4 - (string.length & 3)) & 3)
  end

  # Encode a 4 byte long
  # use to encode:
  #       long element_1;
  def NDR.long(string)
    return [string].pack('V')
  end

  # Encode a 2 byte short
  # use to encode:
  #       short element_1;
  def NDR.short(string)
    return [string].pack('v')
  end

  # Encode a single byte
  # use to encode:
  #       byte element_1;
  def NDR.byte(string)
    return [string].pack('c')
  end

  # Encode a byte array
  # use to encode:
  #       char  element_1
  def NDR.UniConformantArray(string)
    return long(string.length) + string + align(string)
  end

  # Encode a string
  # use to encode:
  #       char *element_1;
  def NDR.string(string)
    string << "\x00" # null pad
    return long(string.length) + long(0) + long(string.length) + string + align(string)
  end

  # Encode a string
  # use to encode:
  #       w_char *element_1;
  def NDR.wstring(string)
    string  = string + "\x00" # null pad
    return long(string.length) + long(0) + long(string.length) + Rex::Text.to_unicode(string) + align(Rex::Text.to_unicode(string))
  end

  # Encode a string and make it unique
  # use to encode:
  #       [unique] w_char *element_1;
  def NDR.uwstring(string)
    string  = string + "\x00" # null pad
    return long(rand(0xffffffff))+long(string.length) + long(0) + long(string.length) + Rex::Text.to_unicode(string) + align(Rex::Text.to_unicode(string))
  end

  # Encode a string that is already unicode encoded
  # use to encode:
  #       w_char *element_1;
  def NDR.wstring_prebuilt(string)
    # if the string len is odd, thats bad!
    if string.length % 2 > 0
      string = string + "\x00"
    end
    len = string.length / 2;
    return long(len) + long(0) + long(len) + string + align(string)
  end

  # alias to wstring, going away soon
  def NDR.UnicodeConformantVaryingString(string)
    NDR.wstring(string)
  end

  # alias to wstring_prebuilt, going away soon
  def NDR.UnicodeConformantVaryingStringPreBuilt(string)
    NDR.wstring_prebuilt(string)
  end

end
end
end

