# -*- coding: binary -*-
require 'msf/core'

class Msf::Encoder::XorDynamic < Msf::Encoder

  def initialize(info)
      super(info)
  end

  def min_key_len
    Integer(datastore['KEYMIN'] || 0)
  end

  def max_key_len
    Integer(datastore['KEYMAX'] || 0)
  end

  def stub
    nil
  end

  def stub_key_term
    nil
  end

  def stub_payload_term
    nil
  end

  def find_key(buf, badchars, keyChars)

    keyFound = nil

    bufLen = buf.length

    # Search for a valid key
    _min_key_len = min_key_len
    if _min_key_len < 1
      _min_key_len = Integer(buf.length / 100 * (0.2 + 0.05 * badchars.length))
      if _min_key_len < 1
        _min_key_len = 1
      end
    end

    _max_key_len = max_key_len
    if _max_key_len < 1
      _max_key_len = buf.length
    end

    for keyLen in _min_key_len.._max_key_len do
      $stderr.print "\rKey size: #{keyLen}"
      $stderr.flush

      myKey = ""
      for x in 0..keyLen - 1 do
        keyChars.each_char do |j|
          ok = true
          i = 0
          while i + x < bufLen do
            if badchars[(buf[i + x].ord ^ j.ord).chr]
              ok = false
              break
            end

            i += keyLen
          end

          if ok
            myKey << j.chr
            break
          end

        end
      end

      if myKey.length == keyLen
        keyFound = myKey
        break
      end
    end

    $stderr.print "\n"
    $stderr.flush
    return keyFound
  end

  def encode(buf, badchars = nil, state = nil, platform = nil)

    # Set default badchars if empty
    badchars = "\x00\x0a\x0d" if (badchars == nil or badchars == '')

    # Check badchars in stub
    if Rex::Text.badchar_index(stub.gsub(stub_key_term, "").gsub(stub_payload_term, ""), badchars)
      raise EncodingError, "Bad character found in stub for the #{self.name} encoder.", caller
    end

    # Set allowed chars
    keyChars = ""
    for i in 1..255 do
      if !badchars[i.chr]
        keyChars << i.chr
      end
    end

    # Find key
    key = find_key(buf, badchars, keyChars)

    if key == nil
      raise NoKeyError, "A key could not be found for the #{self.name} encoder.", caller
    end

    # Search for key terminator
    keyTerm = nil
    keyChars.chars.shuffle.each do |i|
      if !key[i]
        keyTerm = i
        break
      end
    end

    if keyTerm == nil
      raise EncodingError, "Key terminator could not be found for the #{self.name} encoder.", caller
    end

    # Encode paylod
    pos = 0
    encoded = ""
    while pos < buf.length
      encoded << (buf[pos].ord ^ key[pos % key.length].ord).chr
      pos += 1
    end

    # Search for payload terminator
    payloadTerm = nil
    keyChars.chars.shuffle.each do |i|
      break unless keyChars.chars.shuffle.each do |j|
        if !encoded.index(i + j)
          payloadTerm = i + j
          break
        end
      end
    end

    if payloadTerm == nil
      raise EncodingError, "Payload terminator could not be found for the #{self.name} encoder.", caller
    end

    finalPayload = stub.gsub(stub_key_term, keyTerm).gsub(stub_payload_term, payloadTerm) + key + keyTerm + encoded + payloadTerm

    # Check badchars in finalPayload
    if Rex::Text.badchar_index(finalPayload, badchars)
      raise EncodingError, "Bad character found for the #{self.name} encoder.", caller
    end

    return finalPayload
  end
end
