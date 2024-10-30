module Rex::Proto::Teamcity::Rsa
  # https://github.com/openssl/openssl/blob/a08a145d4a7e663dd1e973f06a56e983a5e916f7/crypto/rsa/rsa_pk1.c#L125
  # https://datatracker.ietf.org/doc/html/rfc3447#section-7.2.1
  def self.pkcs1pad2(text, n)
    if n < text.length + 11
      raise ArgumentError, 'Message too long'
    end

    r = Array.new(n, 0)
    n -= 1
    r[n] = text.length

    i = text.length - 1

    while i >= 0 && n > 0
      c = text[i].ord
      i -= 1
      n -= 1
      r[n] = c % 0x100
    end
    n -= 1
    r[n] = 0

    while n > 2
      n -= 1
      r[n] = rand(1..255) # Can't be a null byte.
    end

    n -= 1
    r[n] = 2
    n -= 1
    r[n] = 0

    r.pack("C*").unpack1("H*").to_i(16)
  end

  # @param [String] modulus
  # @param [String] exponent
  # @param [String] text
  # @return [String]
  def self.rsa_encrypt(modulus, exponent, text)
    n = modulus.to_i(16)
    e = exponent.to_i(16)

    padded_as_big_int = pkcs1pad2(text, (n.bit_length + 7) >> 3)
    encrypted = padded_as_big_int.to_bn.mod_exp(e, n)
    h = encrypted.to_s(16)

    h.length.odd? ? h.prepend('0') : h
  end

  # @param [String] text The text to encrypt.
  # @param [String] public_key The hex representation of the public key to use.
  # @return [String] A string blob.
  def self.encrypt_data(text, public_key)
    exponent = '10001'
    e = []
    g = 116 # TODO: wire up d.maxDataSize(f)

    c = 0
    while c < text.length
      b = [text.length, c + g].min

      a = text[c..b]

      encrypt = rsa_encrypt(public_key, exponent, a)
      e.push(encrypt)
      c += g
    end

    e.join('')
  end
end
