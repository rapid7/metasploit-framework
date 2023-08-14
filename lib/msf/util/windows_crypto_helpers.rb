module Msf
module Util
module WindowsCryptoHelpers

  #class Error < RuntimeError; end
  #class Unknown < Error; end

  # Converts DES 56 key to DES 64 key
  #
  # See [2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ebdb15df-8d0d-4347-9d62-082e6eccac40)
  #
  # @param kstr [String] The key to convert
  # @return [String] The converted key
  def convert_des_56_to_64(kstr)
    des_odd_parity = [
      1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
      16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
      32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
      49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
      64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
      81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
      97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
      112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
      128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
      145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
      161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
      176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
      193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
      208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
      224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
      241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
    ]

    key = []
    str = kstr.unpack("C*")

    key[0] = str[0] >> 1
    key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
    key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
    key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
    key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
    key[7] = str[6] & 0x7F

    0.upto(7) do |i|
      key[i] = ( key[i] << 1)
      key[i] = des_odd_parity[key[i]]
    end
    return key.pack("C*")
  end

  # Decrypts "Secret" encrypted data
  #
  # Ruby implementation of SystemFunction005. The original python code
  # has been taken from Credump
  #
  # @param secret [String] The secret to decrypt
  # @param key [String] The key to decrypt the secret
  # @return [String] The decrypted data
  def decrypt_secret_data(secret, key)

    j = 0
    decrypted_data = ''

    for i in (0...secret.length).step(8)
      enc_block = secret[i..i+7]
      block_key = key[j..j+6]
      des_key = convert_des_56_to_64(block_key)
      d1 = OpenSSL::Cipher.new('des-ecb')
      d1.decrypt
      d1.padding = 0
      d1.key = des_key
      d1o = d1.update(enc_block)
      d1o << d1.final
      decrypted_data += d1o
      j += 7
      if (key[j..j+7].length < 7 )
        j = key[j..j+7].length
      end
    end
    dec_data_len = decrypted_data[0,4].unpack('L<').first

    return decrypted_data[8, dec_data_len]

  end

  # Decrypts LSA encrypted data
  #
  # @param policy_secret [String] The encrypted data stored in the registry
  # @param lsa_key [String] The LSA key
  # @return [String] The decrypted data
  def decrypt_lsa_data(policy_secret, lsa_key)

    sha256x = Digest::SHA256.new()
    sha256x << lsa_key
    1000.times do
      sha256x << policy_secret[28,32]
    end

    aes = OpenSSL::Cipher.new("aes-256-cbc")
    aes.decrypt
    aes.key = sha256x.digest

    # vprint_status("digest #{sha256x.digest.unpack("H*")[0]}")

    decrypted_data = ''

    (60...policy_secret.length).step(16) do |i|
      aes.reset
      aes.padding = 0
      aes.iv = "\x00" * 16
      decrypted_data << aes.update(policy_secret[i,16])
    end

    return decrypted_data
  end

  # Derive DES Key1 and Key2 from user RID.
  #
  # @param rid [String] The user RID
  # @return [Array] A two element array containing Key1 and Key2, in this order
  def rid_to_key(rid)
    # See [2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1b0094f-2546-431f-b06d-582158a9f2bb)
    s1 = [rid].pack('V')
    s1 << s1[0, 3]

    s2b = [rid].pack('V').unpack('C4')
    s2 = [s2b[3], s2b[0], s2b[1], s2b[2]].pack('C4')
    s2 << s2[0, 3]

    [convert_des_56_to_64(s1), convert_des_56_to_64(s2)]
  end

  # This decrypt an encrypted NT or LM hash.
  # See [2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a5252e8c-25e7-4616-a375-55ced086b19b)
  #
  # @param rid [String] The user RID
  # @param hboot_key [String] The hashedBootKey
  # @param enc_hash [String] The encrypted hash
  # @param pass [String] The password used for revision 1 hashes
  # @param default [String] The default hash to return if something goes wrong
  # @return [String] The decrypted NT or LM hash
  def decrypt_user_hash(rid, hboot_key, enc_hash, pass, default)
    revision = enc_hash[2, 2]&.unpack('v')&.first

    case revision
    when 1
      return default if enc_hash.length < 20

      md5 = Digest::MD5.new
      md5.update(hboot_key[0, 16] + [rid].pack('V') + pass)

      rc4 = OpenSSL::Cipher.new('rc4')
      rc4.decrypt
      rc4.key = md5.digest
      okey = rc4.update(enc_hash[4, 16])
    when 2
      return default if enc_hash.length < 40

      aes = OpenSSL::Cipher.new('aes-128-cbc')
      aes.decrypt
      aes.key = hboot_key[0, 16]
      aes.padding = 0
      aes.iv = enc_hash[8, 16]
      okey = aes.update(enc_hash[24, 16]) # we need only 16 bytes
    else
      elog("decrypt_user_hash: Unknown user hash revision: #{revision}, returning default")
      return default
    end

    des_k1, des_k2 = rid_to_key(rid)

    d1 = OpenSSL::Cipher.new('des-ecb')
    d1.decrypt
    d1.padding = 0
    d1.key = des_k1

    d2 = OpenSSL::Cipher.new('des-ecb')
    d2.decrypt
    d2.padding = 0
    d2.key = des_k2

    d1o = d1.update(okey[0, 8])
    d1o << d1.final

    d2o = d2.update(okey[8, 8])
    d1o << d2.final
    d1o + d2o
  end

  # Decrypts the user V key value and return the NT amd LM hashes. The V value
  # can be found under the
  # HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\<RID> registry key.
  #
  # @param hboot_key [String] The hashedBootKey
  # @param user_v [String] The user V value
  # @param rid [String] The user RID
  # @return [Array] Array with the first and second element containing the NT and LM hashes respectively
  def decrypt_user_key(hboot_key, user_v, rid)
    sam_lmpass = "LMPASSWORD\x00"
    sam_ntpass = "NTPASSWORD\x00"
    sam_empty_lm = ['aad3b435b51404eeaad3b435b51404ee'].pack('H*')
    sam_empty_nt = ['31d6cfe0d16ae931b73c59d7e0c089c0'].pack('H*')

    # TODO: use a proper structure for V data, instead of unpacking directly
    hashlm_off = user_v[0x9c, 4]&.unpack('V')&.first
    hashlm_len = user_v[0xa0, 4]&.unpack('V')&.first
    if hashlm_off && hashlm_len
      hashlm_enc = user_v[hashlm_off + 0xcc, hashlm_len]
      hashlm = decrypt_user_hash(rid, hboot_key, hashlm_enc, sam_lmpass, sam_empty_lm)
    else
      elog('decrypt_user_key: Unable to extract LM hash, using empty LM hash instead')
      hashlm = sam_empty_lm
    end

    hashnt_off = user_v[0xa8, 4]&.unpack('V')&.first
    hashnt_len = user_v[0xac, 4]&.unpack('V')&.first
    if hashnt_off && hashnt_len
      hashnt_enc = user_v[hashnt_off + 0xcc, hashnt_len]
      hashnt = decrypt_user_hash(rid, hboot_key, hashnt_enc, sam_ntpass, sam_empty_nt)
    else
      elog('decrypt_user_key: Unable to extract NT hash, using empty NT hash instead')
      hashnt = sam_empty_nt
    end

    [hashnt, hashlm]
  end

  # Decrypt a cipher using AES in CBC mode. The key length is deduced from
  # `key` argument length. The supported key length are 16, 24 and 32. Also, it
  # will take care of padding the last block if the cipher length is not modulo
  # 16.
  #
  # @param edata [String] The cipher to decrypt
  # @param key [String] The key used to decrypt
  # @param iv [String] The IV
  # @return [String, nil] The decrypted plaintext or nil if the key size is not supported
  def decrypt_aes(edata, key, iv)
    cipher_str = case key.length
    when 16
      'aes-128-cbc'
    when 24
      'aes-192-cbc'
    when 32
      'aes-256-cbc'
    else
      elog("decrypt_aes: Unknown key length (#{key.length} bytes)")
      return
    end
    aes = OpenSSL::Cipher.new(cipher_str)
    aes.decrypt
    aes.key = key
    aes.padding = 0
    aes.iv = iv

    decrypted = ''
    (0...edata.length).step(aes.block_size) do |i|
      block_str = edata[i, aes.block_size]
      # Pad buffer with \x00 if needed
      if block_str.length < aes.block_size
        block_str << "\x00".b * (aes.block_size - block_str.length)
      end
      decrypted << aes.update(block_str)
    end

    return decrypted
  end

  # Decrypt encrypted cached entry from HKLM\Security\Cache\NL$XX
  #
  # @param edata [String] The encrypted hash entry to decrypt
  # @param key [String] The key used to decrypt
  # @param iv [String] The IV
  # @return [String, nil] The decrypted plaintext or nil if the key size is not supported
  def decrypt_hash(edata, key, iv)
    rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest.new('md5'), key, iv)
    rc4 = OpenSSL::Cipher.new('rc4')
    rc4.decrypt
    rc4.key = rc4key
    decrypted = rc4.update(edata)
    decrypted << rc4.final

    return decrypted
  end

  def add_parity(byte_str)
    byte_str.map do |byte|
      if byte.to_s(2).count('1').odd?
        (byte << 1) & 0b11111110
      else
        (byte << 1) | 0b00000001
      end
    end
  end

  def fix_parity(byte_str)
    byte_str.map do |byte|
      t = byte.to_s(2).rjust(8, '0')
      if t[0, 7].count('1').odd?
        ("#{t[0, 7]}0").to_i(2).chr
      else
        ("#{t[0, 7]}1").to_i(2).chr
      end
    end
  end

  def weak_des_key?(key)
    [
      "\x01\x01\x01\x01\x01\x01\x01\x01",
      "\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE",
      "\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E",
      "\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1",
      "\x01\xFE\x01\xFE\x01\xFE\x01\xFE",
      "\xFE\x01\xFE\x01\xFE\x01\xFE\x01",
      "\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1",
      "\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E",
      "\x01\xE0\x01\xE0\x01\xF1\x01\xF1",
      "\xE0\x01\xE0\x01\xF1\x01\xF1\x01",
      "\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE",
      "\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E",
      "\x01\x1F\x01\x1F\x01\x0E\x01\x0E",
      "\x1F\x01\x1F\x01\x0E\x01\x0E\x01",
      "\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE",
      "\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1"
    ].include?(key)
  end

  # Encrypt using MIT Kerberos des-cbc-md5
  # http://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html?highlight=des#enctype-compatibility
  #
  # @param raw_secret [String] The data to encrypt
  # @param key [String] The salt used by the encryption algorithm
  # @return [String, nil] The encrypted data
  def des_cbc_md5(raw_secret, salt)
    odd = true
    tmp_byte_str = [0, 0, 0, 0, 0, 0, 0, 0]
    plaintext = raw_secret + salt
    plaintext += "\x00".b * (8 - (plaintext.size % 8))
    plaintext.bytes.each_slice(8) do |block|
      tmp_56 = block.map { |byte| byte & 0b01111111 }
      if !odd
        # rubocop:disable Style/FormatString
        tmp_56_str = tmp_56.map { |byte| '%07b' % byte }.join
        # rubocop:enable Style/FormatString
        tmp_56_str.reverse!
        tmp_56 = tmp_56_str.bytes.each_slice(7).map do |bits7|
          bits7.map(&:chr).join.to_i(2)
        end
      end
      odd = !odd
      tmp_byte_str = tmp_byte_str.zip(tmp_56).map { |a, b| a ^ b }
    end
    tempkey = add_parity(tmp_byte_str).map(&:chr).join
    if weak_des_key?(tempkey)
      tempkey[7] = (tempkey[7].ord ^ 0xF0).chr
    end
    cipher = OpenSSL::Cipher.new('DES-CBC')
    cipher.encrypt
    cipher.iv = tempkey
    cipher.key = tempkey
    chekcsumkey = cipher.update(plaintext)[-8..-1]
    chekcsumkey = fix_parity(chekcsumkey.bytes).map(&:chr).join
    if weak_des_key?(chekcsumkey)
      chekcsumkey[7] = (chekcsumkey[7].ord ^ 0xF0).chr
    end
    chekcsumkey.unpack('H*')[0]
  end

  # Encrypt using MIT Kerberos aesXXX-cts-hmac-sha1-96
  # http://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html?highlight=des#enctype-compatibility
  #
  # @param algorithm [String] The AES algorithm to use (e.g. `128-CBC` or `256-CBC`)
  # @param raw_secret [String] The data to encrypt
  # @param key [String] The salt used by the encryption algorithm
  # @return [String, nil] The encrypted data
  def aes_cts_hmac_sha1_96(algorithm, raw_secret, salt)
    iterations = 4096
    cipher = OpenSSL::Cipher::AES.new(algorithm)
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(raw_secret, salt, iterations, cipher.key_len)
    plaintext = "kerberos\x7B\x9B\x5B\x2B\x93\x13\x2B\x93".b
    rnd_seed = ''.b
    loop do
      cipher.reset
      cipher.encrypt
      cipher.iv = "\x00".b * 16
      cipher.key = key
      ciphertext = cipher.update(plaintext)
      rnd_seed += ciphertext
      break unless rnd_seed.size < cipher.key_len

      plaintext = ciphertext
    end
    rnd_seed
  end

  # Encrypt using MIT Kerberos aes128-cts-hmac-sha1-96
  # http://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html?highlight=des#enctype-compatibility
  #
  # @param raw_secret [String] The data to encrypt
  # @param salt [String] The salt used by the encryption algorithm
  # @return [String, nil] The encrypted data
  def aes128_cts_hmac_sha1_96(raw_secret, salt)
    aes_cts_hmac_sha1_96('128-CBC', raw_secret, salt)
  end

  # Encrypt using MIT Kerberos aes256-cts-hmac-sha1-96
  # http://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html?highlight=des#enctype-compatibility
  #
  # @param raw_secret [String] The data to encrypt
  # @param salt [String] The salt used by the encryption algorithm
  # @return [String, nil] The encrypted data
  def aes256_cts_hmac_sha1_96(raw_secret, salt)
    aes_cts_hmac_sha1_96('256-CBC', raw_secret, salt)
  end

  # Encrypt using MIT Kerberos rc4_hmac
  # http://web.mit.edu/kerberos/krb5-latest/doc/admin/enctypes.html?highlight=des#enctype-compatibility
  #
  # @param raw_secret [String] The data to encrypt
  # @param salt [String] The salt used by the encryption algorithm
  # @return [String, nil] The encrypted data
  def rc4_hmac(raw_secret, salt = nil)
    Rex::Proto::Kerberos::Crypto::Rc4Hmac.new.string_to_key(raw_secret, salt)
  end
end
end
end
